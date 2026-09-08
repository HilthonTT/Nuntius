# Users, ACLs, SCRAM, quotas, and TLS

Everything here is **opt-in and backwards compatible**. A broker running the
config it ran yesterday behaves exactly as it did yesterday: one account, full
authority, password authentication, open metrics. What follows is how to stop
doing that.

Confidentiality is [§5, TLS](#5-tls) — also opt-in, and also off by default.

---

## 1. Users

`Auth.Username` + `Auth.PasswordHash` is still valid and still means **one
superuser** — an account that may produce to, consume from, reconfigure, and
delete every topic, and read every group's offsets. That was the only model the
broker had, so upgrading cannot narrow it without breaking deployments.

For more than one tenant, use `Auth.Users`:

```json
"Auth": {
  "Users": [
    { "Username": "admin",
      "PasswordHash": "scram-sha-256$600000$...",
      "Superuser": true },

    { "Username": "orders-svc",
      "PasswordHash": "scram-sha-256$600000$...",
      "Acls": [
        { "Resource": "topic", "Name": "orders.*",
          "Operations": ["read", "write", "describe"] },
        { "Resource": "group", "Name": "orders-*",
          "Operations": ["read", "describe"] }
      ],
      "Quota": { "ProduceRecordsPerSec": 5000 } },

    { "Username": "analytics",
      "PasswordHash": "scram-sha-256$600000$...",
      "Acls": [
        { "Resource": "topic", "Name": "*", "Operations": ["read", "describe"] },
        { "Resource": "topic", "Name": "orders.pii",
          "Operations": "*", "Effect": "deny" },
        { "Resource": "group", "Name": "analytics-*", "Operations": ["read"] }
      ] }
  ],
  "MaxFailures": 5, "FailureWindow": 60, "BanDuration": 900
}
```

`MaxFailures` / `FailureWindow` / `BanDuration` are per **IP**, not per account,
and are shared by both mechanisms — an attacker rotating usernames still trips
one counter.

**Configuration errors are fatal.** An unparseable credential, an unknown
operation, a duplicate username, or an unknown quota key stops the broker at
boot with the offending entry named. A security config that fails open because
of a typo is the failure this is written to prevent. The one non-fatal case is
*no credentials at all*, which remains the documented OPEN mode: the broker
warns and lets everyone do everything.

A user with neither `Superuser` nor `Acls` gets a boot warning: it can
authenticate and then be denied on every request, which is almost always a
forgotten `Acls` block.

### Credential formats

Generate with `make hash PASSWORD=... [ITER=...] [SCRAM=1]`, or
`lua bin/moonmq-hash.lua <password> [iterations] [--scram]`.

| Format | Works with | If the config leaks |
| --- | --- | --- |
| `pbkdf2-sha256$<iter>$<salt>$<hash>` | password + SCRAM | The stored value **is** SCRAM's SaltedPassword, so it is login-equivalent: an attacker authenticates without ever recovering the password. |
| `scram-sha-256$<iter>$<salt>$<stored_key>$<server_key>` | password + SCRAM | Holds only the derived verification keys. Not enough to produce a valid proof. **Prefer this.** |

Both are salted PBKDF2-SHA256 at the same iteration count, and both accept both
mechanisms, so migrating is a config edit with no client change. Existing
`pbkdf2-sha256` hashes keep working untouched.

---

## 2. ACLs

```
resource   := topic | group | cluster
operation  := read | write | create | delete | alter | describe
effect     := allow | deny
name       := "orders" | "orders.*" | "*"
```

Two rules:

* **Default deny.** No matching allow → refused, with `ERR_NOT_AUTHORIZED` (19)
  and a message naming the operation and resource.
* **Deny wins**, regardless of order or specificity. "Everything under
  `orders.*` except `orders.pii`" is two rules and no ordering subtleties.

`Name` is a literal, a prefix (trailing `*`), or `*` for any. `cluster` has no
instances, so any `Name` on it is ignored.

Which operations each resource accepts:

| Resource | Operations |
| --- | --- |
| `topic` | `read` `write` `create` `delete` `alter` `describe` |
| `group` | `read` `delete` `describe` |
| `cluster` | `describe` `alter` `create` |

Anything else — `group:write`, say — is a boot error rather than a rule that
silently never fires.

### What each request checks

| Request | Requires |
| --- | --- |
| `PRODUCE`, `PRODUCE_BATCH`, `PRODUCE_IDEMPOTENT` | `topic:write` |
| `FETCH`, `SUBSCRIBE` | `topic:read` **and** `group:read` |
| `COMMIT`, `NACK` | `topic:read` **and** `group:read` |
| `JOIN_GROUP` | `group:read` and `topic:read` on **every** subscribed topic |
| `TXN_OFFSET_COMMIT` | `group:read` and `topic:read` per offset |
| `CREATE_TOPIC` | `topic:create` on the name, **or** `cluster:create` |
| `DELETE_TOPIC` | `topic:delete` |
| `ALTER_TOPIC_CONFIG` | `topic:alter` |
| `DESCRIBE_TOPIC`, `LIST_OFFSETS` | `topic:describe` |
| `DESCRIBE_GROUP` | `group:describe` |
| `DELETE_GROUP` | `group:delete` |
| `LIST_TOPICS`, `LIST_GROUPS` | *filtered* to what the principal may `describe` |
| `/metrics`, `/stats` (Basic) | `cluster:describe` |

Listings are **filtered, not refused**: a listing that errored because one entry
was off limits would be useless to a tenant, and one that included every name
would leak the shape of everyone else's deployment. Topic and group names are
rarely uninteresting.

Deliberate gaps, so they are choices rather than oversights:

* **`LEAVE_GROUP` / `GROUP_HEARTBEAT` are not checked.** Membership was
  authorized at `JOIN_GROUP`; re-checking would strand a live member whose ACL
  changed mid-session, and neither request grants access to anything.
* **`INIT_PRODUCER_ID` is not checked.** It allocates an identity, not access;
  every produce made under that identity is checked normally.
* **`BEGIN_TXN` / `END_TXN` are not checked.** A transaction is a wrapper around
  produces and offset commits, each of which is checked on its own frame.
* **The dead-letter write is not separately checked.** When a `NACK` exhausts
  its delivery budget the broker moves the record to `<topic>.dlq` on the
  consumer's behalf; `topic:read` on the source topic is the permission that
  gates it. A tenant that must not reach its own DLQ needs an explicit deny on
  that name.
* **Inter-broker endpoints (`/cluster/*`, `/replicate`) are unaffected.** They
  authenticate with `X-Cluster-Token`, not with a user.

---

## 3. SCRAM-SHA-256

An alternative to password authentication that never puts the password on the
wire (RFC 5802 / RFC 7677). Two reasons to prefer it:

1. **The password does not travel.** On a plaintext connection, password AUTH
   hands the credential to anyone on the path.
2. **It costs the broker nothing.** A password login runs a full PBKDF2
   derivation *inline on the single reactor thread* — 0.29 s at the recommended
   600k iterations with luaossl, minutes without it. SCRAM moves that
   derivation to the client; the broker answers with two HMACs and a SHA-256.
   An unauthenticated peer can no longer buy broker CPU by guessing.

Client side, it is one option:

```lua
local c = assert(Client.new{ host = "127.0.0.1", port = 9092,
                             username = "orders-svc", password = "...",
                             mechanism = "scram-sha-256" })
```

The exchange is three frames:

```
AUTH_SCRAM       -> mechanism, "n,,n=orders-svc,r=<client nonce>"
AUTH_CHALLENGE   <- "r=<combined nonce>,s=<salt>,i=<iterations>"
AUTH_SCRAM_FINAL -> "c=biws,r=<combined nonce>,p=<proof>"
AUTH_OK          <- "v=<server signature>"
```

The client verifies that server signature before returning. Skipping that check
would authenticate the client to the broker without authenticating the broker
to the client — most of what an attacker in the middle wants.

Both mechanisms work against both credential formats, and either may be used on
any connection. Both are one-shot: re-authenticating on an established
connection is refused, because it would let a session swap the principal its
ACL is evaluated against mid-stream.

**Unknown usernames are indistinguishable from known ones.** The broker answers
a client-first for a nonexistent account with a decoy credential whose salt and
iteration count are derived from the username — stable across attempts, so a
prober cannot spot the difference, and guaranteed to fail at proof
verification. Password AUTH does the same with a decoy derivation, so response
time does not answer "does this account exist?" either.

Channel binding is advertised as unsupported (`n,,`), which is honest: there is
no TLS channel to bind to yet. The client-final `c=` field is still verified
against the header the client opened with, so a stripped binding request would
be detected the day there is one.

---

## 4. Quotas

Per **principal** and per **topic** token buckets. The existing per-connection
rate limiter bounds one socket, which is not a quota: a tenant with ten
connections gets ten times the budget. Quotas hold however many connections a
client opens.

```json
"Auth": {
  "Quotas": {
    "Default": { "RequestsPerSec": 2000, "ProduceRecordsPerSec": 5000 },
    "Topics":  { "orders": { "ProduceBytesPerSec": 10485760 } },
    "BurstSeconds": 2
  },
  "Users": [
    { "Username": "bulk", "PasswordHash": "...",
      "Quota": { "ProduceRecordsPerSec": 50000 } },
    { "Username": "admin", "PasswordHash": "...", "Superuser": true,
      "Quota": { "ProduceRecordsPerSec": 0 } }
  ]
}
```

| Dimension | Charged on |
| --- | --- |
| `RequestsPerSec` | every gated request |
| `ProduceRecordsPerSec` | records appended |
| `ProduceBytesPerSec` | key + value bytes appended |
| `FetchRecordsPerSec` | records delivered, pull or push |
| `FetchBytesPerSec` | key + value bytes delivered |

* `0` (or absent) means unlimited. An **all-zero block on a user** is how you
  opt that account out of `Default` — an absent block inherits it.
* `BurstSeconds` (default 2) is how much of a second's allowance may be saved up
  and spent at once, so a batching producer is not punished for batching.
* Both the user bucket and the topic bucket must have room; **the more
  restrictive one decides**, and nothing is consumed unless both agree, so a
  busy topic cannot drain a tenant's budget for every other topic.
* A request larger than the whole bucket is charged the bucket rather than
  refused forever — a 10k-record batch against a 1k/s quota is slowed to the
  quota's pace, not rejected in perpetuity.
* Idempotent retries are billed once: the record charge waits until the broker
  knows the append is fresh rather than a replayed ack.

Enforcement differs by path, deliberately. Request/response paths (`PRODUCE`,
`FETCH`, admin) answer `ERR_RATE_LIMITED` (6) with the wait in the message. The
`SUBSCRIBE` push loop has no request to fail, so it is **slowed** by the
interval the quota implies — the same enforcement in the only currency that
path has.

Delivery is metered *after the fact*, because a `FETCH` does not know how many
records it will return until it has read them. So the up-front step is a check
rather than a charge — a consumer still carrying debt from a previous oversized
batch waits, and an empty poll costs it nothing — and the overshoot is carried
as bounded debt that the next request pays. Records are attributed to the topic
they came from, not to the topic named in the frame: one poll can return
everything a consumer subscribes to, and one topic's ceiling should not be paid
out of another's bucket.

Quotas apply to superusers too. Give an admin account an explicit all-zero
block if that is not what you want.

---

## 5. TLS

Off by default. A broker with no `Tls` block anywhere behaves exactly as it did
before, which is what every existing deployment gets on upgrade. What it will
not do is quietly fall back to plaintext on a listener you asked to encrypt: a
missing certificate, an unreadable key, or a `Verify` with nothing to verify
against stops the broker at boot, naming the listener.

Needs **luasec** (`luarocks install luasec`). Without it the broker still boots
and only refuses configurations that ask for TLS.

### Four listeners, four blocks

They have genuinely different exposure, so each configures its own:

| Block | Port | What it protects |
| --- | --- | --- |
| `Server.Tls` | client protocol | Records, keys, topic and group names — everything a client sends or receives |
| `Server.MetricsTls` | `/metrics`, `/stats` | Topic names and sizes; and Basic credentials, if `MetricsAuth.Basic` is on |
| `Server.Cluster.Tls` | `/cluster/*` | The `X-Cluster-Token`, and every record migrated between brokers |
| `Server.Replication.Tls` | `/replicate` | Every record, again — this is the whole log in flight |

```json
"Server": {
  "Tls": {
    "CertFile": "/etc/moonmq/server.crt",
    "KeyFile":  "/etc/moonmq/server.key",
    "HandshakeTimeout": 10
  },
  "MetricsTls": { "CertFile": "…", "KeyFile": "…" },
  "Cluster":     { "Tls": { "CertFile": "…", "KeyFile": "…",
                            "CaFile": "/etc/moonmq/ca.crt",
                            "Verify": "required" } },
  "Replication": { "Tls": { "CertFile": "…", "KeyFile": "…", "Verify": "none" } }
}
```

Keys: `Enabled` (defaults to true when the block exists — writing out cert
paths and getting plaintext because a flag was missing is a trap),
`CertFile`, `KeyFile`, `CaFile`, `CaPath`, `Verify`, `Protocol`, `Ciphers`,
`ServerName`, `HandshakeTimeout`.

`Cluster.Tls` and `Replication.Tls` each configure **both halves** of their
link — the listener and the client that dials peers — from one block, so a
cluster cannot end up encrypted in one direction only.

### Verification

| `Verify` | Server means | Client means |
| --- | --- | --- |
| `none` | Do not ask for a client certificate (default) | Encrypt, but check nothing (`Insecure: true` is a synonym) |
| `peer` | Validate a client certificate if one is offered | Validate the broker's certificate (default) |
| `required` | Refuse any client without a valid certificate — **mTLS** | as `peer` |

Anything other than `none` needs a `CaFile` (or `CaPath`) to validate against.
A **client** with neither falls back to the system trust store
(`/etc/ssl/certs/ca-certificates.crt` and the usual alternatives), which is
what verifying a publicly-signed certificate means everywhere else. A
**listener** never does: `Verify: "required"` there means mTLS against a
private CA, and silently accepting every client signed by any public CA on the
machine would be a severe, silent widening.

Clients also check the **hostname**. luasec validates the certificate chain but
does not check that the name on it is the host you dialled — without that step
any certificate from the trusted CA, including one issued to an attacker for a
name they legitimately control, would be accepted. Both SANs and the common
name are checked, with single-level wildcards (`*.example.com`).

### Clients

```lua
local c = assert(Client.new{
    host = "broker.internal", port = 9092,
    username = "orders-svc", password = "…", mechanism = "scram-sha-256",
    tls = { cafile = "/etc/moonmq/ca.crt" },
})
```

`tls = true` is shorthand for "encrypt and verify against the system trust
store". `tls = { insecure = true }` skips verification — for a self-signed
development broker, and nowhere else. `server_name` overrides the name checked
and sent in SNI, for a broker reached by IP or through a load balancer. Add
`certfile`/`keyfile` for mTLS.

### How it works, and why that part was the work

TLS on a reactor is not a wrapper. On a plain socket, an operation that cannot
proceed says `timeout`, and the direction to wait on is obvious from which
operation it was. On a TLS socket it is not: an encrypted **read** can need the
socket to become **writable** — the record it is decrypting triggered a
renegotiation, or the handshake has not finished — and a write can need
readability for the same reason. luasec reports that as `wantread`/`wantwrite`,
and the only correct response is to wait on the direction the TLS layer asked
for.

That is `Reactor:park` (`src/server/reactor.lua`), and it is what
`read_exact`, `send_all`, `tls_handshake` and the HTTP header readers all go
through. The handshake itself runs as a yielding loop in the accepting
connection's own coroutine, so one peer that opens a socket and then says
nothing stalls only itself, and it is bounded by `HandshakeTimeout`.

For the client listener, a `pre_tls` hook runs **before** the handshake, so a
banned IP is closed without the broker performing one — server-side asymmetric
crypto is exactly the work a lockout exists to stop an abusive peer from
buying. Such a peer gets a TCP close rather than a protocol error frame,
because on a TLS listener there is no session to send one over yet.

### Channel binding

SCRAM proves that both ends know the password. It does not prove that the TLS
connection carrying the exchange is the one the broker terminated — a relay
holding a certificate the client trusts can terminate TLS, replay the SCRAM
messages to the real broker, and own the session afterwards. Channel binding
closes that by mixing something unique to *this* TLS connection into the
exchange.

MoonMQ implements `tls-server-end-point` (RFC 5929): the binding value is the
SHA-256 of the listener's DER-encoded certificate. The server derives it from
`CertFile` at boot; the client derives it from the certificate it was actually
handed during the handshake. A relay presenting a different certificate produces
a different hash, the proof no longer verifies, and the login fails.

It is on by default on any TLS listener and needs nothing from the client
beyond `mechanism = "scram-sha-256"` — the client offers binding whenever it
has a TLS socket:

```json
"Server": { "Tls": { "CertFile": "…", "KeyFile": "…",
                     "ChannelBinding": "preferred" } }
```

| `ChannelBinding` | Behaviour |
| --- | --- |
| `preferred` (default) | Bind whenever the client asks (`p=tls-server-end-point`). An unbound `n,,` client still logs in. |
| `required` | Refuse any SCRAM login that is not bound. |
| `disabled` | Do not offer binding; `p=` is refused. |

The interesting case is the middle one in the gs2 header. A client that
supports binding but believes the *server* does not opens with `y,,`. If this
broker can bind, that belief can only have come from something rewriting the
negotiation, so `y,,` is refused as a downgrade — which is the whole point of
that flag existing. `client_final`'s `c=` field is checked against the gs2
header **plus** the binding value, in constant time, so neither can be swapped
independently.

Passing `channel_binding = false` to `Client.new` opts a client out.

### Not covered

* **Certificate reloading.** A renewed certificate needs a broker restart.
* **Certificate-derived principals.** An mTLS client certificate authenticates
  the *connection*; the MoonMQ principal still comes from AUTH or SCRAM.
* **`tls-unique` binding.** Only `tls-server-end-point` is implemented;
  `tls-unique` is not available under TLS 1.3 anyway.

---

## 6. Metrics endpoint

`/metrics` and `/stats` have always been open, and still are by default —
which is why `MetricsHost` defaults to loopback. `/stats` lists every topic
name and its size on disk.

```json
"Server": {
  "MetricsAuth": { "Token": "a-long-random-string", "Basic": false }
}
```

* **Bearer** — `Authorization: Bearer <token>`, compared in constant time. The
  right choice for a scraper: no KDF, no user store, and the token rotates
  without touching the user list. It can also come from the
  `MOONMQ_METRICS_TOKEN` environment variable, so it need not live in a file
  that ships with the repo.
* **Basic** — `Authorization: Basic base64(user:pass)`, verified against
  `Auth.Users`; the principal must hold `cluster:describe`. Authentication is
  not authorization: a tenant with topic ACLs has no business reading
  broker-wide counters. Repeat scrapes are cheap (the authenticator's success
  cache short-circuits the PBKDF2), and brute force trips the same per-IP
  lockout as the broker port.

Either may be enabled, or both; whichever satisfies the request wins. A 401
carries `WWW-Authenticate` but no detail — a prober cannot tell "wrong token"
from "unknown user" from "no permission". **`/health` is always open**: a
liveness probe that needs a credential is a liveness probe that fails for the
wrong reasons.

---

## 7. Observability

| Metric | Labels |
| --- | --- |
| `moonmq_authz_denied_total` | `resource`, `operation` |
| `moonmq_quota_throttled_total` | `scope` (`user`/`topic`), `dimension` |
| `moonmq_auth_success_total` | `mechanism` (`plain`/`scram`) |
| `moonmq_auth_failures_total` | `mechanism` |
| `moonmq_metrics_http_unauthorized_total` | — |
| `moonmq_tls_handshakes_total` | — |
| `moonmq_tls_handshake_failures_total` | — |

Every denial is also logged with the connection id, the username, the
operation, and the resource, which between them name the ACL rule that is
missing.

---

## 8. Recommended posture

1. Replace the shipped `admin`/`admin` credential (`make hash PASSWORD=... SCRAM=1`).
2. Give every application its own user with the narrowest prefix rules that work.
3. Keep exactly one superuser, and do not use it from applications.
4. Move clients to `mechanism = "scram-sha-256"`.
5. Set a `Default` quota so one misbehaving client cannot starve the rest.
6. Set `MetricsAuth`, or keep `MetricsHost` on loopback.
7. Turn on `Server.Tls`. SCRAM keeps the password off the wire; TLS is what
   keeps the *records* off it.
8. Encrypt the inter-broker links too (`Cluster.Tls`, `Replication.Tls`) — the
   replication port carries the entire log.
9. Watch `moonmq_tls_handshake_failures_total`: a steady nonzero rate is either
   a client that has not been switched over, or someone probing the port.
10. Once every client speaks SCRAM over TLS, set
    `Server.Tls.ChannelBinding: "required"` — it turns "the password is safe"
    into "this session is the one the broker terminated".
