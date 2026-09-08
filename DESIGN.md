# MoonMQ design

How MoonMQ is put together: the layering rule, the path a record takes from a
producer's socket to disk and back out to a consumer, and which module owns
each step. Start here before reading code; the per-feature deep dives in
[`docs/`](docs/) pick up where this leaves off.

- [The one rule](#the-one-rule)
- [Process model](#process-model)
- [Code layout](#code-layout)
- [Produce path](#produce-path)
- [Storage](#storage)
- [Fetch / subscribe path](#fetch--subscribe-path)
- [Consumer groups](#consumer-groups)
- [Batching](#batching)
- [Producer identities & transactions](#producer-identities--transactions)
- [Replication vs clustering](#replication-vs-clustering)
- [Wire protocol](#wire-protocol)
- [Observability](#observability)
- [Where to start reading](#where-to-start-reading)

## The one rule

**Dependencies point downward.** `server` → `broker` → `storage`/`commitlog`
→ `record`/`io`, with `core`/`log`/`metrics` as cross-cutting utilities.
Nothing in a lower layer requires an upper one. If your change needs an upward
reference, pass a callback or attach a factory — see
`Broker:attach_committer_factory` for the pattern.

## Process model

One process, one OS thread, one **reactor** (`src/server/reactor.lua`) — a
cooperative coroutine scheduler over LuaSocket's select loop. Every connection
gets reader/sender/heartbeat coroutines; background jobs (group reaper,
retention cleaner tick, producer-state expiry, balance loop) are just more
coroutines. There are no locks: atomicity between yield points is the
concurrency model. Anything that blocks the loop for long must either yield
periodically (see auth's PBKDF2 slicing) or be tolerated as a documented
design decision — inter-broker HTTP calls are blocking and LAN-appropriate.

## Code layout

Layers, wire down to disk. Each directory depends only on the ones below it
(plus cross-cutting `core`/`log`/`metrics`/`io`); nothing in
`storage`/`commitlog` reaches up into `server`.

```
main.lua           CLI entrypoint: config, logging, auth wiring, server boot
bin/               operational tools (HTTP gateway, password hasher)
src/
  server/          TCP front-end: reactor loop, framing, connection lifecycle,
                   opcode handlers, group coordination, metrics HTTP, and the
                   security layer: users (store) + auth (credentials, lockout)
                   + scram (SCRAM-SHA-256) + acl (permissions) + quota (buckets)
  client/          network client (speaks the wire protocol over TCP)
  wire/            binary protocol codec, shared by server and client
  broker/          domain layer: Broker facade, in-process Producer/Consumer,
                   ConsumerGroup FSM, DLQ, transaction coordinator
  cluster/         multi-broker: ownership table, inter-broker HTTP + peer
                   client, partition reassigner, produce router, balance loop
  cluster/raft/    controller consensus: persistent log store, node state
                   machine, reactor-native RPC, replication service
  autobalancer/    pure decision engine: cluster model, windowed load samples,
                   distribution goals, anomaly detector
  storage/         topic/partition management + default "segmented" backend
                   (segments, time index, group-commit fsync, retention, recovery)
  commitlog/       alternative jocko-style backend: dense offset index,
                   byte-budget retention, key compaction
  record/          on-disk record codec (v2: CRC-framed key/value + attrs byte)
                   plus gzip/snappy compression
  io/              filesystem + durability primitives (fsync, ftruncate, rename)
                   and TLS parameters/wrapping shared by every listener + client
  metrics/ log/    Prometheus registry · leveled logger
  core/            pure utilities (crc32, uuid, rng, futures, time, validation,
                   base64, constant-time compare, PBKDF2)
  fsm/ chaos/      state-machine library · fault-injecting producer wrapper
  repl/            interactive MQL console (sql/ lexer→parser→executor)
  vendor/          vendored third-party code (sha2)
  examples/        runnable client examples
spec/              busted test suite + standalone storage smoke test
```

## Produce path

```
client ──frame──> server/connection.lua   (framing, state machine, deadlines)
                  server/handlers.lua     (opcode → handler; PRODUCE decodes,
                                           compresses value if requested)
                  broker/producer.lua     (partition pick: keyed FNV-1a or
                                           sticky; acks handling)
                  cluster/router.lua      (only in a cluster: forward to the
                                           partition's owner if not local)
                  storage/segmentation.lua  or  storage/commitlog_partition.lua
                                          (append + fsync policy)
```

* `acks=none` — ack after the in-memory append.
* `acks=leader` — ack after fsync. Concurrent producers coalesce into ONE
  fsync via the group committer (`storage/group_committer.lua`).
* `acks=all` — additionally wait until every configured follower's LEO
  covers the record (`server/replicator.lua`).

## Storage

Two interchangeable backends behind one duck-typed partition interface
(`write_message` / `read_message` / `oldest_offset` / `offset` / `sync` /
`scan` / `close`), selected per topic:

* **segmented** (`storage/segmentation.lua`, default): byte-offset log.
  Segment files roll at a size threshold; a sparse timeindex maps timestamps
  to file positions; retention deletes whole aged-out segments; recovery
  CRC-verifies the unclean tail and truncates torn records.
* **commitlog** (`src/commitlog/`, jocko-style): message-offset log with a
  dense offset index per segment, byte-budget retention, and key compaction
  (latest record per key survives; offsets renumber — see the caveat in
  `compact_cleaner.lua`).

The on-disk record format (`src/record/message.lua`) is shared:
`len(8) | header(13) | hdr_crc(4) | key | value | payload_crc(4)`, with an
attrs byte carrying the compression codec and the transaction-control flag.

Internal topics (name prefix `__`) reuse the same machinery: consumer offsets
(`__consumer_offsets`), producer state (`__producer_state`), transaction state
(`__transaction_state`). They run on the commitlog backend because compaction —
not time retention — is the right bound for latest-value-per-key state.

## Fetch / subscribe path

Pull (`FETCH`) spreads its `max_records` budget across the partitions the
caller may read (`ceil(max_records / pollable_partitions)` each), so a
4-partition topic no longer caps a 100-record fetch at 4 records; push
(`SUBSCRIBE`) runs a per-connection delivery coroutine. Both commit an offset
only **after** the record is handed to the send layer — at-least-once delivery.
A connection is either a pull consumer or a push consumer; mixing the two on
one connection is rejected.

Under `read_committed` isolation (an optional trailing byte on
FETCH/SUBSCRIBE) a consumer stops at the partition's **Last Stable Offset** and
skips records belonging to aborted transactions —
see [docs/transactions.md](docs/transactions.md).

Redelivery is implicit: an uncommitted offset simply comes back next poll. A
record the consumer can *never* process is broken out of that loop by `NACK`
and the dead-letter queue — see [docs/dlq.md](docs/dlq.md).

## Consumer groups

A topic's partitions are shared across a group so each partition has exactly
one owner. `src/broker/groups.lua` tracks membership, assigns partitions with a
Kafka-style **range** strategy, and ages out members that stop heartbeating
(30s session deadline, reaped every 10s). Durable per-group offsets live in the
internal `__consumer_offsets` topic, so a rebalanced consumer resumes from its
committed position.

The lifecycle is an explicit FSM (`src/fsm/state_machine.lua`), mirroring
Kafka's GroupCoordinator:

```
        join (1st member)        membership settled       assignments synced
empty ──────────────────▶ preparing_rebalance ─▶ completing_rebalance ─▶ stable
  ▲                              │                                          │
  │ last member leaves / evicted │  another join or leave triggers a new    │
  └──────────────────────────────┴──────────── rebalance ◀──────────────────┘

  any state ──close()──▶ dead   (terminal: join/leave/heartbeat all reject)
```

A single broker drives joins synchronously, so one `join`/`leave` walks
straight through `preparing → completing → stable`. The FSM still pays its way:
state is inspectable (`group:state()`), illegal operations are guarded (you
can't heartbeat a `dead` group), and every transition logs in one place.

Over the wire a client uses `JOIN_GROUP` / `GROUP_HEARTBEAT` / `LEAVE_GROUP`.
The broker keeps one `ConsumerGroup` per group id shared across member
connections; a connection is at most one member, and when it drops the broker
departs on its behalf and rebalances the survivors.

`FETCH`/`SUBSCRIBE` **honor the assignment**: each member reads only its
partitions. The broker re-derives the live assignment before each poll
(`GroupCoordinator:apply_assignment` → `Consumer:set_assignment`), so a
rebalance takes effect on the next fetch without pushing a new frame. An
evicted member is pinned to "own nothing" until it re-joins; a member that
leaves reverts to reading every subscribed partition. `GROUP_MEMBER_UNKNOWN`
means the member was reaped — re-`join_group`. Joining a second group on one
connection is rejected with `GROUP_CONFLICT`.

A runnable in-process walkthrough of the whole lifecycle lives at
`src/examples/consumer_group.lua`.

## Batching

One record used to cost one frame, one dispatch, one round trip, and — under
`acks=1` — one fsync. `PRODUCE_BATCH` amortises all four: N records travel in
one frame and pay **one fsync per partition the batch touched**.

A batch is N ordinary appends sharing a frame, not an atomic unit: records are
partitioned individually, and a failure part-way through durably keeps the
prefix and reports the error, so the client resends only the tail. Wrap it in a
transaction if you need all-or-nothing.

On the read side, `FETCH` can ask for its records in a single `RECORD_BATCH`
frame (a flags-byte bit old brokers simply stop decoding at), and the broker
drains several records per partition per poll.

Idempotent batches extend the single-record contract: record *i* carries
sequence `base_seq + i`, and an exact resend replays the batch's memoized acks
instead of appending duplicates — across a broker restart, for durable
producers. Wire formats and limits: [docs/batching.md](docs/batching.md).

## Producer identities & transactions

The broker assigns a producer ID (PID) on demand and dedupes retries of the
same `(PID, topic, seq)` by replaying the original `(partition, offset)`
instead of appending a duplicate. `INIT_PRODUCER_ID` with a `producer_name`
gives a producer a stable PID whose epoch bumps each session, so stale sessions
are fenced (`ERR_PRODUCER_FENCED`). Dedup is scoped *within an epoch* — a
reconnect restarts sequences at 0, KIP-360 style.

Out-of-order or skipped sequences are rejected with
`ERR_OUT_OF_ORDER_SEQUENCE`, letting the client detect lost records;
`ERR_NO_PRODUCER_ID` fires if `PRODUCE_IDEMPOTENT` arrives before
`INIT_PRODUCER_ID`.

Transactions (`broker/txn_coordinator.lua`) buffer offset commits and write
COMMIT/ABORT control markers to participants; recovery rolls prepared decisions
forward and aborts abandoned ones. Consumers reading `read_committed` floor
their reads at the Last Stable Offset and filter aborted data records via
`broker/abort_index.lua`. Full semantics:
[docs/transactions.md](docs/transactions.md).

## Replication vs clustering

Two orthogonal features, both statically configured:

* **Replication** (`server/replicator.lua` + `replica_server.lua`):
  single-leader full-copy for durability. The leader ships every record to
  followers over `POST /replicate`; `acks=all` blocks on follower LEOs. No
  election.
* **Clustering** (`src/cluster/` + `src/autobalancer/`): partition *placement*
  for load distribution — ownership table, live partition migration, produce
  forwarding, autobalancer. Consumer groups span the cluster (each group hashes
  to one coordinator broker), committed offsets migrate with a partition, and
  transactional produce works across brokers. See
  [docs/cluster.md](docs/cluster.md).

* **Controller consensus** (`src/cluster/raft/`, optional): a replicated log
  over cluster *metadata* only — which broker is controller, which broker owns
  which partition. It makes the epoch on `/cluster/*` requests a majority-agreed
  Raft term instead of a local monotonic counter, and confines the balance loop
  to the elected leader. The message log is never replicated through it.

How both were scoped and where they landed:
[docs/roadmap-security-consensus.md](docs/roadmap-security-consensus.md).

## Wire protocol

Clients and the broker speak a compact binary protocol over TCP
(`src/wire/protocol.lua`). Integers are big-endian, strings are
length-prefixed (`u32`) UTF-8, every frame is length-prefixed:

```
┌──────────────┬────────┬────────────────┬──────────────┐
│ FrameLen(4B) │ Op(1B) │ CorrelID(16B)  │ Payload(var) │
└──────────────┴────────┴────────────────┴──────────────┘
```

`FrameLen` covers everything after itself. `CorrelID` is a 16-byte UUID. There
is no application-level CRC — TCP guarantees transport integrity, and on-disk
records carry their own CRC since the disk layer can corrupt independently.

Opcodes split into client requests (`0x01`–`0x7F`) and server replies
(`0x80`–`0xFE`):

| Client → server | Purpose |
| --- | --- |
| `HELLO` · `AUTH` | Protocol-version handshake · password authentication |
| `AUTH_SCRAM` · `AUTH_SCRAM_FINAL` | SCRAM-SHA-256 client-first · client-final (answered by `AUTH_CHALLENGE`, then `AUTH_OK` carrying the server signature) |
| `PRODUCE` · `PRODUCE_BATCH` | Append one record · append N in one frame |
| `FETCH` · `SUBSCRIBE` | Pull a batch · stream on arrival |
| `COMMIT` · `NACK` | Commit a group offset · reject a record (→ DLQ) |
| `CREATE_TOPIC` · `LIST_TOPICS` · `LIST_OFFSETS` | Topic admin · per-partition offset bounds (and offset-for-timestamp) |
| `DELETE_TOPIC` · `DESCRIBE_TOPIC` · `ALTER_TOPIC_CONFIG` | Remove a topic · read its config · change it |
| `LIST_GROUPS` · `DESCRIBE_GROUP` · `DELETE_GROUP` | Consumer-group admin |
| `INIT_PRODUCER_ID` · `PRODUCE_IDEMPOTENT` | Request a u64 PID · append `(PID, seq, …)` |
| `BEGIN_TXN` · `END_TXN` · `TXN_OFFSET_COMMIT` | Transaction lifecycle |
| `JOIN_GROUP` · `GROUP_HEARTBEAT` · `LEAVE_GROUP` | Consumer-group membership |
| `IDENTIFY_CLIENT` · `GOODBYE` | Client metadata · clean disconnect |
| `HEARTBEAT_REQ` · `HEARTBEAT_RESP` | Connection liveness (bidirectional) |

| Server → client | Purpose |
| --- | --- |
| `WELCOME` · `AUTH_OK` · `IDENTIFY_ACK` | Handshake / auth acceptance |
| `PRODUCE_ACK` · `PRODUCE_BATCH_ACK` | Partition + offset · one pair per batched record |
| `PRODUCER_ID` · `GROUP_ASSIGNMENT` | Assigned u64 PID · member id + partitions |
| `RECORD` · `RECORD_BATCH` | A delivered record · N of them in one frame |
| `TOPIC_LIST` · `OFFSETS` · `OK` · `NACK_ACK` | Query results / acks |
| `TOPIC_DESCRIPTION` · `GROUP_LIST` · `GROUP_DESCRIPTION` | Admin query results |
| `ERROR` | Numeric error code + message |

A connection must `HELLO` then `AUTH` before anything else; only handshake
opcodes are accepted pre-auth.

`src/server/server.lua` owns the listener, capacity accounting, and ban
enforcement, then delegates to `src/server/connection.lua`. Each `Connection`
runs three coroutines — reader, sender (bounded send queue), heartbeat probe —
driven by a `new → greeted → authenticated → closed` state machine, with
framing isolated in `src/server/framer.lua` and 16-byte connection/correlation
IDs from `src/core/uuid.lua`. A watchdog drops connections that fail to
authenticate within `HandshakeDeadline`.

TLS, when a listener configures it (`src/io/tls.lua`), is wrapped around the
socket before any of that: the reactor performs the handshake in the accepting
connection's own coroutine and hands `on_accept` an already-encrypted socket,
so everything above this line is unchanged by it. The one place TLS is visible
is `Reactor:park` — an encrypted read can need the socket to become *writable*,
and every read, write, handshake and HTTP header parse waits on the direction
the TLS layer asks for rather than the one the caller intended.

## Observability

Two HTTP endpoints on `MetricsHost:MetricsPort` (default `127.0.0.1:9090`).
**Unauthenticated unless `Server.MetricsAuth` is set** (bearer token or HTTP
Basic against the user store) — otherwise keep it on loopback or firewall the
port. `/health` is open either way.

**`GET /metrics`** — Prometheus exposition format:

| Metric | Type | Labels |
| --- | --- | --- |
| `moonmq_connections_open` | gauge | — |
| `moonmq_connections_accepted_total` | counter | — |
| `moonmq_connections_closed_total` | counter | `reason` |
| `moonmq_bytes_sent_total` · `moonmq_frames_sent_total` | counter | — |
| `moonmq_frames_received_total` | counter | `op` |
| `moonmq_send_duration_seconds` | histogram | — |
| `moonmq_dispatch_duration_seconds` | histogram | `op` |
| `moonmq_produce_records_total` · `moonmq_idempotent_produce_total` · `moonmq_produce_batches_total` · `moonmq_fetch_records_total` · `moonmq_segment_rolls_total` | counter | `topic` |
| `moonmq_fsync_duration_seconds` | histogram | `topic` |
| `moonmq_topic_count` | gauge | — |
| `moonmq_partition_log_bytes` | gauge | `topic`, `partition` |
| `moonmq_authz_denied_total` | counter | `resource`, `operation` |
| `moonmq_quota_throttled_total` | counter | `scope`, `dimension` |
| `moonmq_auth_success_total` · `moonmq_auth_failures_total` | counter | `mechanism` |
| `moonmq_tls_handshakes_total` · `moonmq_tls_handshake_failures_total` | counter | — |

`moonmq_partition_log_bytes` is per-partition — a few thousand series at the
default `MaxTopics=1024`, which is fine for Prometheus. Lift `MaxTopics`
cautiously.

**`GET /stats`** — bounded JSON snapshot (version, open connections, topic
count, top 10 topics by bytes on disk) for `curl | jq` inspection. Use
`/metrics` for monitoring agents.

Label cardinality is bounded by construction: never label by anything unbounded
such as a connection id.

## Where to start reading

| If you want to understand… | Start at |
| --- | --- |
| the event loop | `src/server/reactor.lua` (~270 lines, self-contained) |
| a request's lifecycle | `src/server/connection.lua`, then `handlers.lua` |
| who may do what | `src/server/acl.lua`, then the gates in `handlers.lua` |
| TLS | `src/io/tls.lua`, then `Reactor:park` / `tls_handshake` |
| the wire protocol | `src/wire/protocol.lua` (every frame documented) |
| the disk format | `src/record/message.lua`, then `storage/segmentation.lua` |
| crash recovery | `storage/segment_verify.lua` + `Broker:load_topics` |
| consumer groups | `src/broker/groups.lua` + `src/server/group_coordinator.lua` |
| transactions | `src/broker/txn_coordinator.lua` + `docs/transactions.md` |
| the balancer | `src/autobalancer/init.lua`, then `docs/cluster.md` |
