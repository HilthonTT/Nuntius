<p align="center">
  <img src="assets/logo.jpg" alt="MoonMQ logo" width="180" style="border-radius: 16px;" />
</p>

<h1 align="center">MoonMQ</h1>

<p align="center">
  A log-structured, partitioned message broker written in <b>pure Lua</b>.
</p>

<p align="center">
  <a href="https://github.com/HilthonTT/MoonMQ/actions/workflows/ci.yml"><img src="https://github.com/HilthonTT/MoonMQ/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/Lua-5.4-2C2D72?logo=lua&logoColor=white" alt="Lua 5.4" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT" />
</p>

---

Clients connect over TCP and speak a compact binary protocol to produce
records, fetch or subscribe to topics, create topics, and commit consumer
offsets. Topics are partitioned append-only logs with CRC-checked on-disk
records.

| | |
| --- | --- |
| **Storage** | Segmented log with time + offset indexes, group-commit fsync, retention, crash recovery. Alternative jocko-style commitlog backend with key compaction. |
| **Delivery** | Pull (`FETCH`) or push (`SUBSCRIBE`), consumer groups with a range assignor and durable offsets, DLQ with NACK. |
| **Throughput** | Record batching on both sides: one frame for N records, one fsync per partition instead of per record. |
| **Correctness** | Idempotent producer (PID + sequence dedupe), multi-partition transactions, `read_committed` isolation with LSO. |
| **Cluster** | Static-membership peers, AutoMQ-style autobalancer, live partition migration, cluster-wide consumer groups, single-leader replication with `acks=all`. |
| **Admin** | Create/describe/delete topics, alter topic config at runtime, list/describe/delete consumer groups, seek by timestamp. |
| **Security** | TLS on every listener (mutual TLS optional, `SIGHUP` reloads certificates), multiple users with per-topic/group/cluster ACLs, SCRAM-SHA-256 with `tls-server-end-point` channel binding, per-user and per-topic quotas, optional auth on the metrics port. |
| **Ops** | Prometheus `/metrics`, JSON `/stats`, PBKDF2 auth with per-IP lockout, an interactive SQL-like console (MQL). |

## Quick start

```bash
sudo apt install lua5.4 lua-socket libssl-dev zlib1g-dev   # Debian/Ubuntu
make deps          # busted, dkjson, luasocket, luaposix, lua-zlib, luaossl, luasec
lua5.4 main.lua    # or: make run
```

```
[main] env=Development host=0.0.0.0 port=9092 data_dir=./data_server
[server] listening on 0.0.0.0:9092 (proto v1, MoonMQ/v0.01)
```

Ctrl+C (SIGINT) shuts down cleanly. `lua5.4 main.lua --repl` opens the MQL
console instead — a small SQL-like language over the wire protocol
(`CREATE TOPIC`, `PRODUCE INTO`, `FETCH FROM`, `JOIN GROUP`, …). Grammar:
[docs/mql.md](docs/mql.md), or `HELP;` in-session.

```lua
local Client = require("src.client")
local c = assert(Client.new{ host = "127.0.0.1", port = 9092,
                             username = "admin", password = "admin",
                             idempotent = true })

local ack   = assert(c:produce("orders", "key-1", "payload"))  -- {partition, offset, seq}
local acks  = assert(c:produce_batch("orders", {              -- one frame, one fsync/partition
    { key = "k1", value = "v1" },
    { key = "k2", value = "v2" },
}))
local res   = assert(c:join_group("billing", { "orders" }))    -- {member_id, assignment}
local ends  = assert(c:list_offsets("orders"))                 -- per partition {earliest, latest, …}
```

`list_offsets` reports where each partition starts and ends, which is what
makes lag (`latest - committed`) computable and what lets a consumer seek to
either end. Under `read_committed` measure against `lso` instead — that is the
offset the broker will actually deliver up to.

To seek by wall-clock rather than by offset, `offsets_for_times` resolves the
earliest offset per partition whose record timestamp is at or after a given
millisecond timestamp — Kafka's `offsetForTimes`. It reads the sparse
`.timeindex` every partition already writes, so it is a short binary search
plus a bounded scan rather than a walk of the log:

```lua
local at = assert(c:offsets_for_times("orders", 1700000000000))
-- { { partition = 1, offset = 8134, found = true }, ... }
```

`found = false` means nothing at or after that time exists yet; `offset` is
then the partition's `latest`, i.e. where the first such record will land, so
"seek to T and follow" works on a partition that has not reached T yet.

Admin calls round out the surface — topics can be described, reconfigured and
deleted at runtime, and consumer groups inspected:

```lua
assert(c:alter_topic_config("orders", { retention = 86400 }))  -- seconds
local d = assert(c:describe_group("billing"))
-- d.members[i].assignment, d.offsets[i] = { topic, partition, offset }
```

Pairing `describe_group`'s committed offsets with `list_offsets` is what makes
lag a broker-side fact rather than something a sidecar has to reconstruct. A
group holding committed offsets but no live members — an abandoned or
between-deploys consumer — shows up in `list_groups` with state `empty`, which
is usually the thing you went looking for.

Runnable examples: `src/examples/tcp_client.lua`,
`src/examples/consumer_group.lua`.

## Requirements

- **Lua 5.4** — uses native bitwise operators and `goto`/labels
- **LuaSocket** — TCP networking
- **dkjson** — pure-Lua JSON, reads `appsettings.json`
- **luaposix** (Linux) — real `fsync`/`ftruncate`, so `acks=1` actually hits
  disk. Also gives `src/io/fs.lua` syscall-based directory access: without it
  every `is_dir`/`read_dir`/`mkdir` forks a process **on the reactor thread**
  (measured on ext4: 23 ms per `test -d` against 2.5 µs for a `stat`, and 42
  process spawns just to open ten partitions)
- **lua-zlib** — gzip compression *and* the native CRC-32 every record is
  checksummed with. The pure-Lua fallback runs at ~16 MB/s against ~740 MB/s
- **luaossl** — native PBKDF2 for password verification. Without it a login
  costs **3.2 s of reactor time at 10,000 iterations and ~190 s at the
  recommended 600,000**, versus 5 ms and 0.29 s natively. Needs `libssl-dev`
- **luasec** — TLS on the client, metrics, cluster and replication listeners.
  Without it the broker still boots and only refuses configurations that ask
  for TLS. Needs `libssl-dev`

luaposix is **required** on Linux — `src/io/io_sync.lua` has no other way to
fsync. lua-zlib, luaossl and luasec are optional: without them the broker still
boots and falls back to pure Lua (or, for luasec, to plaintext-only), logging
which backend it picked (`filesystem backend=…`, `PBKDF2 backend=…`) at
startup. Those fallbacks are correct, not fast — a production broker wants
them all. Snappy compression additionally
needs LuaJIT FFI + `libsnappy`; SHA-256/HMAC is vendored
(`src/vendor/sha2.lua`) with nothing to install.

`make deps` installs the lot.

<details>
<summary><b>Building luaposix for Lua 5.4</b> (Ubuntu's package only ships 5.1–5.3)</summary>

```bash
sudo apt install liblua5.4-dev autoconf automake libtool
git clone --depth 1 --branch v36.2.1 https://github.com/luaposix/luaposix.git /tmp/luaposix
cd /tmp/luaposix
lua5.4 build-aux/luke package=luaposix version=36.2.1 \
    PREFIX=/usr/local LUA=lua5.4 \
    LUA_INCDIR=/usr/include/lua5.4 \
    LUA_LIBDIR=/usr/lib/x86_64-linux-gnu \
    INST_LIBDIR=/usr/local/lib/lua/5.4 \
    INST_LUADIR=/usr/local/share/lua/5.4
sudo lua5.4 build-aux/luke install package=luaposix version=36.2.1 \
    PREFIX=/usr/local LUA=lua5.4 \
    LUA_INCDIR=/usr/include/lua5.4 \
    LUA_LIBDIR=/usr/lib/x86_64-linux-gnu \
    INST_LIBDIR=/usr/local/lib/lua/5.4 \
    INST_LUADIR=/usr/local/share/lua/5.4
```

Verify: `lua5.4 -e 'print(require("posix.unistd").fsync)'` should print a function.

</details>

<details>
<summary><b>Windows</b></summary>

`src/io/io_sync.lua` falls back to LuaJIT FFI (`_commit`, `_chsize_s` from the
C runtime), so Windows needs **LuaJIT** rather than stock Lua 5.4.

</details>

## Configuration

`appsettings.json` in the working directory, deep-merged with
`appsettings.<MOONMQ_ENVIRONMENT>.json` when present (default environment:
`Development`).

| Section | Keys |
| --- | --- |
| `Server` | `Host`, `Port` (9092), `DataDir`, `MaxConnections` (960), `MaxConnectionsPerIP`, `FdReserve` (64), `MaxFrameSize`, `MaxTopics` (1024), `MaxListTopics`, `IdleDeadline` (60s), `PreAuthReadDeadline` (5s), `HandshakeDeadline` (5s), `Tls`, `MetricsHost`, `MetricsPort` (`null` disables), `MetricsTls`, `MetricsAuth`, `Acks`, `Replication`, `Cluster`, `Autobalance` |
| `Auth` | `Username` + either `PasswordHash` (`pbkdf2-sha256$…` or `scram-sha-256$…`) or plaintext `Password`; `MaxFailures`, `FailureWindow`, `BanDuration` for per-IP lockout. `Users` (multi-tenant list with `Acls` + `Quota`) and `Quotas` (`Default`/`Topics`/`BurstSeconds`) — see [docs/security.md](docs/security.md) |
| `Logging` | `Level` (`DEBUG`/`INFO`/`WARN`/`ERROR`), `File` (empty = stderr only), `LogToStderr` (default true, tees both) |

`MaxConnections` is a ceiling, not a promise: the event loop multiplexes with
`select(2)`, which cannot watch a descriptor numbered at or above
`FD_SETSIZE` (1024 on Linux). The broker clamps the configured value to
`FD_SETSIZE` minus a reserve for listeners and the log files each open
partition holds, logs the clamp, and refuses any connection whose descriptor
lands above the line — one refused connection instead of a dead broker. A node
with many partitions should raise the reserve (`Server.FdReserve`); watch
`moonmq_connections_refused_fd_total` to see whether the budget is too tight.

Generate a password hash — 600 000 PBKDF2 iterations per NIST 2024 guidance
(existing hashes keep their stored iteration count):

```bash
make hash PASSWORD=yourpw
```

> [!IMPORTANT]
> Verification cost scales linearly with the iteration count, it runs **inline
> on the single reactor thread**, and the stored hash carries its own iteration
> count — so a 600 000-iteration hash generated on a host with luaossl is
> still accepted by a broker without it, where it takes minutes per login.
> The broker measures this at startup and warns when a login would cost more
> than a second; install luaossl, or re-hash with a count the host can afford
> (`lua bin/moonmq-hash.lua <password> <iterations>`).

> [!WARNING]
> With no usable credential the broker starts **open** (no authentication)
> and logs a warning. Every listener is **plaintext** until a `Tls` block says
> otherwise, and the metrics endpoints are unauthenticated by default — set
> `Server.MetricsAuth`, or keep `MetricsHost` on loopback.

### Users, ACLs, SCRAM, quotas

A lone `Auth.Username` is a **superuser**: it may produce to, consume from,
reconfigure and delete every topic. For more than one tenant, replace it with
`Auth.Users` — each entry carrying its own credential, its own ACL, and
optionally its own quota:

```json
"Auth": {
  "Users": [
    { "Username": "admin", "PasswordHash": "scram-sha-256$600000$…",
      "Superuser": true },
    { "Username": "orders-svc", "PasswordHash": "scram-sha-256$600000$…",
      "Acls": [
        { "Resource": "topic", "Name": "orders.*",
          "Operations": ["read", "write", "describe"] },
        { "Resource": "group", "Name": "orders-*", "Operations": ["read"] }
      ],
      "Quota": { "ProduceRecordsPerSec": 5000 } }
  ]
}
```

ACLs are default-deny and deny-wins, over `topic` / `group` / `cluster` with
literal, prefix (`orders.*`) or `*` names. `LIST_TOPICS` and `LIST_GROUPS` are
*filtered* rather than refused, so a tenant sees its own slice of the broker and
nothing else. A refused request gets `ERR_NOT_AUTHORIZED` naming the operation
and resource, so the missing rule is obvious from the client's log.

**SCRAM-SHA-256** (`mechanism = "scram-sha-256"` on the client) is worth
switching to for two reasons: the password never crosses the wire — which
matters on a plaintext connection — and the PBKDF2 derivation happens on the
*client*, so a login no longer costs the broker's single reactor thread 0.29 s
(or minutes, without luaossl). Credentials come in two formats, both accepted by
both mechanisms:

```bash
make hash PASSWORD=yourpw SCRAM=1   # scram-sha-256$… — preferred
make hash PASSWORD=yourpw           # pbkdf2-sha256$… — login-equivalent if leaked
```

Quotas are token buckets keyed by principal and by topic, which is what the
per-connection rate limiter is not — a tenant cannot buy more budget by opening
more sockets.

### TLS

Off by default; every listener configures its own block, because a public
client port and a loopback scrape endpoint are not the same problem:

```json
"Server": {
  "Tls":         { "CertFile": "/etc/moonmq/server.crt",
                   "KeyFile":  "/etc/moonmq/server.key" },
  "MetricsTls":  { "CertFile": "…", "KeyFile": "…" },
  "Cluster":     { "Tls": { "CertFile": "…", "KeyFile": "…",
                            "CaFile": "/etc/moonmq/ca.crt",
                            "Verify": "required" } },
  "Replication": { "Tls": { "CertFile": "…", "KeyFile": "…" } }
}
```

```lua
local c = assert(Client.new{ host = "broker.internal", port = 9092,
                             username = "orders-svc", password = "…",
                             mechanism = "scram-sha-256",
                             tls = { cafile = "/etc/moonmq/ca.crt" } })
```

SCRAM over TLS additionally binds the exchange to the connection. The binding
value is the SHA-256 of the listener's certificate (`tls-server-end-point`),
so a relay that terminates TLS with a certificate of its own and replays the
SCRAM messages to the real broker fails the proof — and a client that claims
the broker cannot bind, when it can, is refused as a downgrade rather than
quietly logged in. It is on by default; `"ChannelBinding": "required"` refuses
any unbound SCRAM login once every client has been switched over.

`SIGHUP` reloads every TLS listener's certificate without a restart. The new
certificate and key are pushed through OpenSSL first, and a reload that cannot
produce a usable context is refused with the running one kept — a renewal typo
should not cost you the listener.

`Verify: "required"` on a listener is mutual TLS — a client without a valid
certificate is refused. Clients verify the chain *and* the hostname (luasec
checks only the chain, which would accept any certificate the CA ever issued).
A misconfigured block is fatal at boot rather than a silent fall back to
plaintext.

The interesting part is not the crypto but the event loop: an encrypted read
can need the socket to become *writable*, which no plaintext socket ever does.
`Reactor:park` waits on the direction TLS asks for, and every read, write,
handshake and HTTP header parse goes through it.

Full reference, including exactly which permission each request checks:
**[docs/security.md](docs/security.md)**.

There is no built-in log rotation — pair `Logging.File` with `logrotate(8)`
using `copytruncate` (the broker holds the FD open). If the path can't be
opened it logs a one-time WARN and falls back to stderr.

Clustering is configured under `Server.Cluster` / `Server.Autobalance`:

```json
"Server": {
  "Cluster":     { "BrokerId": "b1", "Port": 9095,
                   "Peers": [ { "Id": "b2", "Address": "10.0.0.2:9095" } ] },
  "Autobalance": { "IntervalSeconds": 60, "DryRun": true }
}
```

## Testing

```bash
make check         # luacheck + busted + storage smoke test — what CI runs
make test          # busted only
make smoke         # standalone restart/recovery + segment-roll test
```

Roughly one spec per module under `spec/`, plus pinned regression suites
(`bugfix_regression_spec.lua`, `review_fixes_spec.lua`) and a chaos suite that
drives fault injection through `ChaosProducer`.

<details>
<summary><b>Debian/Ubuntu dependency caveats</b></summary>

- The default `luarocks` launcher targets **Lua 5.1**; the Makefile invokes
  `luarocks-5.4` explicitly so deps land in `/usr/local/{share,lib}/lua/5.4`.
- LuaRocks' HTTPS fetcher can fail with `bad argument #2 to 'method' (string
  expected, got light userdata)` on boxes with broken luasec. The Makefile sets
  `fs_use_modules = false` so downloads route through `wget`/`curl` — run
  `sudo apt install wget` first.
- For a system-wide install run `make deps` with `sudo`; otherwise pass
  `LUAROCKS="luarocks-5.4 --local"`.
- `make deps` installs `busted` at `/usr/local/bin/busted` bound to Lua 5.4,
  overwriting any Lua-5.1 busted on PATH (preserved as `busted~`).

</details>

## Documentation

**New here?** Read [DESIGN.md](DESIGN.md) — layering, module map, the produce
and fetch paths, wire protocol, and metrics — then
[CONTRIBUTING.md](CONTRIBUTING.md).

| Doc | Covers |
| --- | --- |
| [DESIGN.md](DESIGN.md) | Architecture: layering, code layout, data flow, wire protocol, observability |
| [docs/cluster.md](docs/cluster.md) | Clustering, partition reassignment, autobalancer |
| [docs/transactions.md](docs/transactions.md) | Idempotent producer, transactions, `read_committed` |
| [docs/batching.md](docs/batching.md) | Batch wire formats, guarantees, limits |
| [docs/dlq.md](docs/dlq.md) | Dead-letter queue and NACK semantics |
| [docs/security.md](docs/security.md) | TLS, users, ACLs, SCRAM-SHA-256, quotas, metrics-endpoint auth |
| [docs/mql.md](docs/mql.md) | The interactive console's SQL-like grammar |
| [docs/roadmap-security-consensus.md](docs/roadmap-security-consensus.md) | Scoped-but-unshipped: controller consensus (TLS has since shipped) |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |

## Credits

MoonMQ stands on the shoulders of these projects and write-ups:

| Project | What it gave MoonMQ |
| --- | --- |
| [**jocko**](https://github.com/travisjeffery/jocko) — Kafka in Go | The commitlog backend design: dense offset index, byte-budget retention, key compaction |
| [**lua-state-machine**](https://github.com/kyleconroy/lua-state-machine) | The FSM library behind the consumer-group and connection lifecycles |
| [**luaprompt**](https://github.com/dpapavas/luaprompt) | Interactive-console foundations |
| [**croissant**](https://github.com/giann/croissant) | REPL structure and rendering ideas |
| [**AutoMQ**](https://github.com/AutoMQ/automq) | The autobalancer model: windowed load samples, distribution goals, anomaly detection |
| [**Building a Kafka clone in Go**](https://support.tools/post/building-kafka-clone-in-go/) | Broker architecture walkthrough |

Licensed under the [MIT License](LICENSE).
