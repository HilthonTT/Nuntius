# Roadmap notes: TLS (shipped) and controller consensus

Two design gaps assessed on 2026-07-19, alongside the batch that shipped
producer-state expiry, cross-broker transactional produce, and cluster-wide
consumer groups. Both are implementable; neither is a bolt-on. This note
records the integration points so the work can start without re-scoping.

> **Update (2026-08-29). TLS has shipped** — along with multi-user auth, ACLs,
> SCRAM-SHA-256, quotas and metrics-endpoint authentication. See
> [security.md](security.md); the TLS section below is kept as the record of
> what was planned and how it actually landed.
>
> It went in essentially as scoped, in the order the note recommended. What is
> worth recording is that step (2) really was the whole difficulty: the
> readiness handling is `Reactor:park`, which routes `wantread`/`wantwrite` to
> the direction the TLS layer asks for rather than the one the caller intended,
> and `read_exact`, `send_all`, the handshake loop and the HTTP header readers
> all go through it. Steps (1), (3) and (4) were then mechanical — every
> listener takes `{ tls = … }` from `Reactor:listen` and receives an
> already-encrypted socket, and the two HTTP clients take a `create` function.
>
> Two departures from the plan below:
>
> * **Configuration is per listener, not one global block**: `Server.Tls`,
>   `Server.MetricsTls`, `Cluster.Tls`, `Replication.Tls`. The four have
>   genuinely different exposure, and the cluster/replication blocks configure
>   both halves of their link at once so it cannot be encrypted in one
>   direction only.
> * **A `pre_tls` hook runs before the handshake**, so a banned IP is refused
>   without the broker performing the asymmetric crypto — a lockout that still
>   pays for a handshake is not much of a lockout.
>
> **Update (2026-09-08). Both remaining TLS items have shipped.** SCRAM
> channel binding (`tls-server-end-point`) went in as scoped: the binding value
> is SHA-256 over the listener's DER certificate, derived from `CertFile`
> server-side and from `getpeercertificate()` client-side, and `check_cbind`
> now compares the gs2 header *concatenated with* that value. The part worth
> recording is the `y,,` case — a client that supports binding but thinks the
> server does not. Treating it as a plain unbound login would have made the
> whole feature bypassable, so a broker that *can* bind refuses `y,,` outright.
> `ChannelBinding` is `preferred` by default and `required` is available.
>
> Certificate reload is `SIGHUP`. The mechanism is smaller than expected —
> `Reactor:listen` already reads `tls_cfg.params` per accept, so swapping the
> table is enough — and the work was in refusing a bad swap: the new params are
> pushed through `ssl.newcontext` before they replace the running ones, and a
> failure keeps the old config rather than converting a renewal typo into a
> dead listener. The handler only sets a flag; the reload runs on the reactor.

## TLS (client protocol + inter-broker HTTP) — SHIPPED

**Status when this was written:** everything is plaintext — the client TCP protocol, the
`/replicate` follower endpoint, the `/cluster/*` peer endpoints, and
`/metrics`. The documented posture is loopback binds, private networks,
`X-Cluster-Token`, and firewalls.

**Toolchain:** luasec is available (1.3.2 verified in the WSL toolchain) and
is the right dependency: `ssl.wrap(sock, params)` + `dohandshake()` over
luasocket sockets, which is what every socket here already is.

**Why it isn't a small patch:** the broker runs its own reactor
(`src/server/reactor.lua`) with non-blocking sockets. A TLS handshake (and
every TLS read/write) can return `wantread`/`wantwrite` instead of
completing, so TLS must be woven into the event loop, not wrapped around it:

1. **Accept path** (`server.lua` / `reactor:listen`): after accept, wrap and
   drive `dohandshake()` as a reactor-yielding loop with a deadline (reuse
   the handshake watchdog). Wrap BEFORE the HELLO/AUTH state machine.
2. **Read/write paths** (`reactor.lua` `read_exact` / send loops): treat
   `wantread`/`wantwrite` like `timeout` — reschedule on the appropriate
   readiness set. This is the core change; everything else rides on it.
3. **HTTP servers** (`cluster_server.lua`, `replica_server.lua`,
   `metrics_http.lua` via `http_kit`): same wrap-at-accept, then unchanged.
4. **HTTP clients** (`cluster/peer.lua`, `server/replica.lua`): luasocket's
   `http.request` accepts a `create` function — return a TLS-wrapped socket
   there (or switch URLs to `https://` with `ssl.https`), plus CA/verify
   options.
5. **Config:** per-listener `Tls = { CertFile, KeyFile, CaFile, Verify }`
   under `Server`, `Cluster`, `Replication`, `Metrics`; peers get
   `Tls = true` + CA. Config-gated so plaintext deployments are untouched.

**Suggested order:** (2) reactor readiness handling → (1) client listener →
(3)/(4) cluster + replication → metrics last. Ship with socket-level
integration tests (the current spec suite drives routes in-process and would
not exercise the handshake paths at all).

## Controller consensus (beyond epoch fencing)

**Status today:** `controller_fence.lua` is fencing, not consensus — a
durable monotonic epoch, propagated on requests, refusing superseded
controllers with 409. Split-brain is possible when two claimants act against
disjoint reachable peers, and epoch-less requests bypass the fence.

**Recommended shape:** a minimal Raft, scoped ONLY to cluster metadata — not
the data path. The replicated log would carry three entry types:

- controller claims (replacing the ad-hoc epoch file as source of truth),
- partition ownership changes (the `assignments` table — today last-writer-
  wins JSON per broker),
- group-coordinator liveness hints (optional, later).

Data stays single-leader-per-partition exactly as now; Raft's job is to make
"who owns what" and "who is controller" agree everywhere, which removes both
documented split-brain caveats at once.

**Integration points:** `cluster/controller_fence.lua` (replace `observe`
with leader lease), `cluster/assignments.lua` (apply committed entries
instead of local `set_owner`), `cluster/balance_loop.lua` (run only on the
Raft leader), `cluster_server.lua` (one new route pair: RequestVote /
AppendEntries). Static membership from `Cluster.Peers` is fine for v1 —
no joint consensus needed.

**Not recommended:** trying to Raft-replicate the message log itself. That
is a different project (and the AutoMQ-style architecture this codebase
follows deliberately avoids it).

## Interim mitigations (already in place)

- `X-Cluster-Token` shared secret on every inter-broker request.
- Controller epoch headers + durable fence on mutating routes.
- Loopback-by-default binds for cluster/replication/metrics listeners.
