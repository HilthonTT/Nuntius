local socket           = require("socket")
local Reactor          = require("src.server.reactor")
local fs_m             = require("src.io.fs")
local proto            = require("src.wire.protocol")
local Connection       = require("src.server.connection")
local handlers         = require("src.server.handlers")
local GroupCoordinator = require("src.server.group_coordinator")
local uuid             = require("src.core.uuid")
local brk_m            = require("src.broker")
local prd_m            = require("src.broker.producer")
local metrics          = require("src.metrics")
local MetricsHttp      = require("src.server.metrics_http")
local tls_m            = require("src.io.tls")
local Replicator       = require("src.server.replicator")
local ReplicaServer    = require("src.server.replica_server")
local replica_m        = require("src.server.replica")
local version_m        = require("src.core.version")
local Assignments      = require("src.cluster.assignments")
local Peer             = require("src.cluster.peer")
local Router           = require("src.cluster.router")
local Reassigner       = require("src.cluster.reassigner")
local ClusterServer    = require("src.cluster.cluster_server")
local BalanceLoop      = require("src.cluster.balance_loop")
local ControllerFence  = require("src.cluster.controller_fence")
local RaftStore        = require("src.cluster.raft.store")
local RaftNode         = require("src.cluster.raft.node")
local RaftService      = require("src.cluster.raft.service")
local RaftFence        = require("src.cluster.raft.fence")
local log              = require("src.log.logger").get("server")

local ACKS_BY_NAME = {
    none   = prd_m.AckMode.AckNone,
    leader = prd_m.AckMode.AckLeader,
    all    = prd_m.AckMode.AckAll,
}

local function build_replicator(reactor, rc)
    if not rc or not rc.enabled then return nil end
    local role = rc.role or "leader"
    if role ~= "leader" and role ~= "both" then return nil end
    local followers = {}
    for _, peer in ipairs(rc.peers or {}) do
        followers[#followers + 1] = {
            id     = peer.id,
            client = replica_m.ReplicaClient.new(peer.address, rc.ack_timeout,
                { tls = rc.tls }),
        }
    end
    if #followers == 0 then return nil end
    return Replicator.new(reactor, rc.replica_id or 1, followers, {
        lag_max     = rc.lag_max,
        ack_timeout = rc.ack_timeout,
    })
end

local DEFAULT_MAX_FRAME           = 1 * 1024 * 1024
local DEFAULT_MAX_PENDING_BYTES   = 16 * 1024 * 1024
local DEFAULT_SEND_DEADLINE       = 30
local DEFAULT_HANDSHAKE_DEADLINE  = 5
local DEFAULT_PRE_AUTH_READ_DEADLINE = 5
local DEFAULT_IDLE_DEADLINE          = 60
local DEFAULT_HEARTBEAT_INTERVAL  = 30
local DEFAULT_HEARTBEAT_MISS      = 3
local DEFAULT_PUSH_INTERVAL       = 0.05
local DEFAULT_PUSH_BATCH          = 256
local DEFAULT_MAX_CONNECTIONS = 1024
local DEFAULT_FD_RESERVE = 64

local DEFAULT_MAX_TOPICS = 1024
local DEFAULT_MAX_LIST_TOPICS = 1024
local DEFAULT_GROUP_COMMIT_LINGER_S    = 0.002
local DEFAULT_GROUP_COMMIT_MAX_WAITERS = 64
local DEFAULT_GROUP_REAPER_INTERVAL_S  = 10
local DEFAULT_MAX_GROUPS = 1024
local DEFAULT_CLEANER_TICK_INTERVAL_S = 5
local DEFAULT_PRODUCER_EXPIRY_S       = 24 * 60 * 60
local DEFAULT_PRODUCER_EXPIRY_CHECK_INTERVAL_S = 300
local TLS_RELOAD_POLL_S = 1

local Server = {}
Server.__index = Server

function Server.new(opts)
    opts = opts or {}
    assert(opts.data_dir, "opts.data_dir required")

    local broker, berr = brk_m.Broker.new(opts.data_dir, {
        default_backend = opts.default_backend,
        dlq             = opts.dlq,
        -- With a cluster, txn recovery must wait for the router (below).
        transactions    = { defer_recovery = opts.cluster ~= nil },
    })
    if not broker then return nil, berr end

    metrics.set("moonmq_topic_count", #broker:list_topics())

    local vinfo = version_m.GetVersionInfo()
    metrics.describe("moonmq_build_info", "gauge", "Build metadata; value is always 1.")
    metrics.set("moonmq_build_info", 1,
        { version = vinfo.version, commit = vinfo.git_commit })
    metrics.describe("moonmq_topic_count", "gauge", "Number of user topics.")
    metrics.describe("moonmq_connections_open", "gauge", "Currently open connections.")
    metrics.describe("moonmq_connections_refused_fd_total", "counter",
        "Connections refused because their descriptor exceeded the select limit.")
    metrics.describe("moonmq_produce_records_total", "counter", "Records produced.")
    metrics.describe("moonmq_fetch_records_total", "counter", "Records delivered to consumers.")
    metrics.describe("moonmq_produce_batches_total", "counter",
        "PRODUCE_BATCH frames accepted (records land in moonmq_produce_records_total).")
    metrics.describe("moonmq_producers_expired_total", "counter",
        "Idle durable producer identities expired from __producer_state.")
    metrics.describe("moonmq_nack_total", "counter",
        "Processing failures reported by consumers via NACK.")
    metrics.describe("moonmq_dlq_records_total", "counter",
        "Records moved to a dead-letter topic.")
    metrics.describe("moonmq_authz_denied_total", "counter",
        "Requests refused by an ACL, labelled by resource and operation.")
    metrics.describe("moonmq_quota_throttled_total", "counter",
        "Requests refused or delayed by a quota, labelled by scope and dimension.")
    metrics.describe("moonmq_auth_success_total", "counter",
        "Successful authentications, labelled by mechanism.")
    metrics.describe("moonmq_auth_failures_total", "counter",
        "Failed authentications, labelled by mechanism.")
    metrics.describe("moonmq_metrics_http_unauthorized_total", "counter",
        "Metrics-endpoint requests refused for missing or bad credentials.")
    metrics.describe("moonmq_raft_term", "gauge",
        "Current controller-consensus term on this broker.")
    metrics.describe("moonmq_raft_is_controller", "gauge",
        "1 when this broker is the elected controller, 0 otherwise.")
    metrics.describe("moonmq_raft_commit_index", "gauge",
        "Highest committed index in the controller metadata log.")
    metrics.describe("moonmq_raft_elections_total", "counter",
        "Controller elections this broker has started.")
    metrics.describe("moonmq_tls_handshakes_total", "counter",
        "Completed TLS handshakes across every listener.")
    metrics.describe("moonmq_tls_reloads_total", "counter",
        "TLS listener configurations revalidated and swapped in on SIGHUP.")
    metrics.describe("moonmq_tls_reload_failures_total", "counter",
        "SIGHUP reloads refused because the new certificate or key was unusable.")
    metrics.describe("moonmq_tls_handshake_failures_total", "counter",
        "TLS handshakes that failed: an untrusted or missing client "
        .. "certificate, a plaintext client on a TLS port, or a stalled peer.")

    local reactor = Reactor.new({ fd_limit = opts.fd_limit })

    local fd_reserve = opts.fd_reserve or DEFAULT_FD_RESERVE
    local watchable  = math.max(1, reactor.fd_limit - fd_reserve)
    local requested_connections = opts.max_connections or DEFAULT_MAX_CONNECTIONS
    local max_connections       = requested_connections
    if max_connections > watchable then
        max_connections = watchable
        log:warn("max_connections %d exceeds what select can watch "
            .. "(fd limit %d, reserving %d for listeners/log files); "
            .. "capping at %d",
            requested_connections, reactor.fd_limit, fd_reserve, max_connections)
    end

    local replicator = build_replicator(reactor, opts.replication)

    local cluster = nil
    local cc = opts.cluster
    if cc and cc.enabled ~= false then
        assert(type(cc.broker_id) == "string" and #cc.broker_id > 0,
            "cluster.broker_id required")
        local assignments, aerr = Assignments.new(opts.data_dir, cc.broker_id)
        if not assignments then return nil, aerr end

        local fence, ferr = ControllerFence.new(opts.data_dir)
        if not fence then return nil, ferr end

        local peers = {}
        local addresses, tokens, member_ids = {}, {}, { cc.broker_id }
        for _, p in ipairs(cc.peers or {}) do
            peers[p.id] = Peer.new(p.id, p.address,
                { token = p.token or cc.token, timeout = cc.peer_timeout,
                  tls = cc.tls })
            addresses[p.id]  = p.address
            tokens[p.id]     = p.token or cc.token
            member_ids[#member_ids + 1] = p.id
        end

        broker.cluster_assignments = assignments

        local raft_node, raft_service
        local rf = cc.raft
        if rf and rf.enabled ~= false then
            local store, rerr = RaftStore.new(opts.data_dir)
            if not store then return nil, rerr end

            raft_node = RaftNode.new({
                id              = cc.broker_id,
                peers           = member_ids,
                store           = store,
                election_min    = rf.election_min,
                election_max    = rf.election_max,
                max_log_entries = rf.max_log_entries,
                apply = function(entry)
                    if entry.kind ~= RaftNode.KIND_OWNER then return true end
                    local d = entry.data
                    if type(d.topic) ~= "string" or type(d.partition) ~= "number"
                       or type(d.owner) ~= "string" then
                        return true
                    end
                    return assignments:set_owner(d.topic, d.partition, d.owner)
                end,
                snapshot = function()
                    return { owners = assignments:entries() }
                end,
                restore = function(state)
                    return assignments:replace(
                        type(state) == "table" and state.owners or {})
                end,
            })

            raft_service = RaftService.new({
                node        = raft_node,
                reactor     = reactor,
                addresses   = addresses,
                tokens      = tokens,
                token       = cc.token,
                tls         = cc.tls,
                heartbeat_s = rf.heartbeat_s,
                rpc_timeout = rf.rpc_timeout,
                commit_wait = rf.commit_wait,
            })
            fence = RaftFence.new(raft_node)
        end

        cluster = {
            broker_id   = cc.broker_id,
            assignments = assignments,
            peers       = peers,
            router      = Router.new({
                assignments = assignments, peers = peers, self_id = cc.broker_id,
            }),
            reassigner  = Reassigner.new({
                broker = broker, assignments = assignments, peers = peers,
                self_id = cc.broker_id, reactor = reactor,
                batch_bytes = cc.batch_bytes,
                raft_commit = raft_service and function(topic, partition, owner)
                    return raft_service:commit(RaftNode.KIND_OWNER, {
                        topic = topic, partition = partition, owner = owner,
                    })
                end or nil,
            }),
            host  = cc.host or "127.0.0.1",
            port  = cc.port,
            token = cc.token,
            fence = fence,
            raft  = raft_node,
            raft_service = raft_service,
            server_tls = cc.server_tls,
        }
    end

    local acks = opts.acks
    if type(acks) == "string" then acks = ACKS_BY_NAME[acks:lower()] end
    if acks == nil then acks = prd_m.AckMode.AckLeader end
    local producer = prd_m.Producer.new(broker, acks, {
        replicator = replicator,
        router     = cluster and cluster.router or nil,
    })

    if cluster and broker.transactions then
        broker.transactions:set_router(cluster.router)
    end
    if broker.transactions and broker.transactions.recover then
        local rok, rerr = broker.transactions:recover()
        if not rok then return nil, rerr end
    end

    local server = setmetatable({
        broker      = broker,
        producer    = producer,
        reactor     = reactor,
        replicator  = replicator,
        replication = opts.replication,
        cluster     = cluster,
        autobalance = opts.autobalance,
        coordinator = GroupCoordinator.new(broker, {
            max_groups = opts.max_groups or DEFAULT_MAX_GROUPS,
            cluster    = cluster and {
                self_id = cluster.broker_id,
                peers   = cluster.peers,
            } or nil,
        }),
        host        = opts.host or "0.0.0.0",
        port        = opts.port or 9092,


        max_frame                = opts.max_frame                or DEFAULT_MAX_FRAME,
        max_pending_bytes        = opts.max_pending_bytes        or DEFAULT_MAX_PENDING_BYTES,
        send_deadline            = opts.send_deadline            or DEFAULT_SEND_DEADLINE,
        handshake_deadline       = opts.handshake_deadline       or DEFAULT_HANDSHAKE_DEADLINE,
        pre_auth_read_deadline   = opts.pre_auth_read_deadline   or DEFAULT_PRE_AUTH_READ_DEADLINE,
        idle_deadline            = opts.idle_deadline            or DEFAULT_IDLE_DEADLINE,
        heartbeat_interval       = opts.heartbeat_interval       or DEFAULT_HEARTBEAT_INTERVAL,
        heartbeat_miss_threshold = opts.heartbeat_miss_threshold or DEFAULT_HEARTBEAT_MISS,
        push_interval            = opts.push_interval            or DEFAULT_PUSH_INTERVAL,
        push_batch               = opts.push_batch               or DEFAULT_PUSH_BATCH,
        max_topics               = opts.max_topics               or DEFAULT_MAX_TOPICS,
        max_list_topics          = opts.max_list_topics          or DEFAULT_MAX_LIST_TOPICS,

        max_connections        = max_connections,
        max_connections_per_ip = opts.max_connections_per_ip or 32,
        connections            = 0,
        conn_by_ip             = {},
        connections_by_id      = {},

        metrics_host = opts.metrics_host or "127.0.0.1",
        metrics_port = opts.metrics_port,

        authenticator        = opts.authenticator,
        rate_limiter_factory = opts.rate_limiter_factory,
        quotas               = opts.quotas,
        metrics_auth         = opts.metrics_auth,
        tls                  = opts.tls,
        metrics_tls          = opts.metrics_tls,

        group_commit_linger_s    = opts.group_commit_linger_s
                                   or DEFAULT_GROUP_COMMIT_LINGER_S,
        group_commit_max_waiters = opts.group_commit_max_waiters
                                   or DEFAULT_GROUP_COMMIT_MAX_WAITERS,

        group_reaper_interval = opts.group_reaper_interval
                                or DEFAULT_GROUP_REAPER_INTERVAL_S,
        cleaner_tick_interval = opts.cleaner_tick_interval
                                or DEFAULT_CLEANER_TICK_INTERVAL_S,
        producer_expiry_s     = opts.producer_expiry_s
                                or DEFAULT_PRODUCER_EXPIRY_S,
        producer_expiry_check_interval = opts.producer_expiry_check_interval
                                or DEFAULT_PRODUCER_EXPIRY_CHECK_INTERVAL_S,
        running               = false,
    }, Server)

    broker.group_coordinator = server.coordinator

    return server
end

function Server:_register_conn(ip)
    if self.connections >= self.max_connections then
        return false, "server at capacity"
    end
    local n = self.conn_by_ip[ip] or 0
    if n >= self.max_connections_per_ip then
        return false, "too many connections from this address"
    end
    self.connections = self.connections + 1
    self.conn_by_ip[ip] = n + 1
    return true
end

function Server:_unregister_conn(conn)
    if self.connections_by_id[conn.id] == nil then return end
    self.connections_by_id[conn.id] = nil

    self.coordinator:handle_disconnect(conn)

    if conn.in_txn and conn.producer_name then
        pcall(function()
            self.broker.transactions:end_txn(
                conn.producer_name, conn.pid, conn.epoch, false)
        end)
        conn.in_txn = false
    end

    if self.connections > 0 then
        self.connections = self.connections - 1
    end
    local n = (self.conn_by_ip[conn.ip] or 1) - 1
    if n <= 0 then
        self.conn_by_ip[conn.ip] = nil
    else
        self.conn_by_ip[conn.ip] = n
    end

    metrics.set("moonmq_connections_open", self.connections)
end

function Server:_refuse(sock, frame)
    pcall(function()
        self.reactor:send_all(sock, frame, socket.gettime() + 0.25)
    end)
    pcall(function() sock:close() end)
end

function Server:_handle(sock, peer, ip)
    if self.authenticator and self.authenticator.is_banned then
        local banned, remaining = self.authenticator:is_banned(ip)
        if banned then
            local f = proto.encode_error(uuid.ZERO, proto.ERR_AUTH_FAILED,
                string.format("banned for %ds", remaining))
            self:_refuse(sock, f)
            return
        end
    end

    local reg_ok, reason = self:_register_conn(ip)
    if not reg_ok then
        local f = proto.encode_error(uuid.ZERO, proto.ERR_RATE_LIMITED, reason)
        self:_refuse(sock, f)
        return
    end

    local made_ok, conn = pcall(Connection.new, self, sock, peer, ip)
    if not made_ok then
        log:error("Connection.new failed for %s: %s", ip, tostring(conn))
        if self.connections > 0 then self.connections = self.connections - 1 end
        local n = (self.conn_by_ip[ip] or 1) - 1
        self.conn_by_ip[ip] = n > 0 and n or nil
        pcall(function() sock:close() end)
        return
    end
    self.connections_by_id[conn.id] = conn

    metrics.inc("moonmq_connections_accepted_total")
    metrics.set("moonmq_connections_open", self.connections)

    local start_ok, start_err = pcall(conn.start, conn)
    if not start_ok then
        log:error("conn=%s start failed: %s",
            conn.id_short, tostring(start_err))
        conn:close(Connection.REASON_READ_ERROR)
    end
end

function Server:dispatch(conn, op, correl, payload)
    local stop = metrics.timer(
        "moonmq_dispatch_duration_seconds",
        { op = string.format("0x%02x", op) })

    local handler = handlers.BY_OP[op]
    if handler then
        handler(self, conn, correl, payload)
    else
        conn:send(proto.encode_error(correl, proto.ERR_UNKNOWN_OP,
            string.format("op 0x%02X", op)))
    end

    stop()
end

function Server:_every(interval, name, fn)
    while self.running do
        self.reactor:sleep(interval)
        if not self.running then return end
        local ok, err = pcall(fn)
        if not ok then log:error("%s: %s", name, tostring(err)) end
    end
end

function Server:_run_group_reaper()
    self:_every(self.group_reaper_interval, "group reaper", function()
        self.coordinator:reap()
    end)
end

function Server:_run_cleaner_tick()
    self:_every(self.cleaner_tick_interval, "cleaner tick", function()
        self.broker:tick_cleaners()
    end)
end

function Server:_run_producer_expiry()
    local max_idle_ms = self.producer_expiry_s * 1000
    self:_every(self.producer_expiry_check_interval, "producer expiry sweep", function()
        local expired, err = self.broker:expire_idle_producers(max_idle_ms, {
            is_active = function(_name, pid)
                for _, conn in pairs(self.connections_by_id) do
                    if conn.pid == pid then return true end
                end
                return false
            end,
        })
        if err then
            log:warn("producer expiry sweep incomplete (%d expired): %s",
                expired or 0, tostring(err))
        elseif expired and expired > 0 then
            metrics.inc("moonmq_producers_expired_total", expired)
        end
    end)
end

function Server:_install_signal_handlers()
    local ok, signal = pcall(require, "posix.signal")
    if not ok then
        log:warn("luaposix missing, no signal handling")
        return
    end

    local function on_signal(signo)
        log:info("got signal %d, shutting down", signo)
        self.reactor:stop()
    end

    signal.signal(signal.SIGINT,  on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGTSTP, on_signal)

    if signal.SIGHUP then
        signal.signal(signal.SIGHUP, function()
            self.tls_reload_requested = true
        end)
        log:info("SIGHUP reloads TLS certificates without a restart")
    end
end

function Server:reload_tls()
    local reloaded, rotated, errors = tls_m.reload_all()
    for _, err in ipairs(errors) do
        log:error("TLS reload: %s", err)
    end
    if reloaded > 0 then metrics.inc("moonmq_tls_reloads_total", reloaded) end
    if #errors > 0 then
        metrics.inc("moonmq_tls_reload_failures_total", #errors)
    end
    log:info("TLS reload: %d listener(s) revalidated, %d certificate(s) changed, "
        .. "%d refused", reloaded, rotated, #errors)
    return reloaded, rotated, errors
end

function Server:_run_tls_reload_watch()
    while self.running do
        self.reactor:sleep(TLS_RELOAD_POLL_S)
        if self.tls_reload_requested then
            self.tls_reload_requested = false
            local ok, err = pcall(self.reload_tls, self)
            if not ok then log:error("TLS reload failed: %s", tostring(err)) end
        end
    end
end

function Server:start()
    local _, err = self.reactor:listen(self.host, self.port,
        function(sock, peer, ip) self:_handle(sock, peer, ip) end,
        {
            tls = self.tls,
            pre_tls = function(_sock, _peer, ip)
                if not (self.authenticator and self.authenticator.is_banned) then
                    return true
                end
                return not self.authenticator:is_banned(ip)
            end,
        })
    if err then return nil, err end

    local linger      = self.group_commit_linger_s
    local max_waiters = self.group_commit_max_waiters
    local reactor     = self.reactor
    self.broker:attach_committer_factory(function(p)
        p:attach_committer(reactor, {
            linger_s    = linger,
            max_waiters = max_waiters,
        })
    end)
    log:info("group commit: linger=%.3fs max_waiters=%d",
        linger, max_waiters)

    self:_install_signal_handlers()

    if self.authenticator and self.authenticator.set_yield_fn then
        self.authenticator:set_yield_fn(function() reactor:sleep(0) end)
    end

    self.running = true
    self.reactor:spawn(function() self:_run_group_reaper() end)
    self.reactor:spawn(function() self:_run_cleaner_tick() end)
    self.reactor:spawn(function() self:_run_tls_reload_watch() end)
    if self.producer_expiry_s and self.producer_expiry_s > 0 then
        self.reactor:spawn(function() self:_run_producer_expiry() end)
    end

    log:info("listening on %s:%d (proto v%d, %s/%s, %s)",
        self.host, self.port, proto.PROTOCOL_VERSION,
        proto.SERVER_NAME, proto.SERVER_VERSION, tls_m.describe(self.tls))

    if not self.tls and self.host ~= "127.0.0.1" and self.host ~= "localhost"
       and self.host ~= "::1" then
        log:warn("client listener on %s:%d is PLAINTEXT: records, topic names "
            .. "and group names are readable on the path. Configure Server.Tls, "
            .. "or keep the broker on a private network.", self.host, self.port)
    end

    if fs_m.backend == "shell" then
        log:warn("filesystem backend=shell: every directory check forks a "
            .. "process on the reactor thread. Install luaposix "
            .. "(luarocks install luaposix) for syscall-based file I/O.")
    else
        log:info("filesystem backend=%s, connection cap=%d (fd limit %d)",
            fs_m.backend, self.max_connections, self.reactor.fd_limit)
    end

    if self.metrics_port then
        local mh = MetricsHttp.new({
            reactor = self.reactor,
            host    = self.metrics_host,
            port    = self.metrics_port,
            server  = self,
            auth          = self.metrics_auth,
            authenticator = self.authenticator,
            tls           = self.metrics_tls,
        })
        mh:start()
    end

    if self.cluster and self.cluster.port then
        local cs = ClusterServer.new({
            reactor     = self.reactor,
            broker      = self.broker,
            assignments = self.cluster.assignments,
            broker_id   = self.cluster.broker_id,
            host        = self.cluster.host,
            port        = self.cluster.port,
            token       = self.cluster.token,
            tls         = self.cluster.server_tls,
            fence       = self.cluster.fence,
            raft        = self.cluster.raft,
            group_coordinator = self.coordinator,
        })
        cs:start()

        if self.cluster.raft_service then
            self.reactor:spawn(function()
                self.cluster.raft_service:run(function() return self.running end)
            end)
            log:info("controller consensus: raft over %d member(s), "
                .. "restored at term %d index %d",
                self.cluster.raft:size(), self.cluster.raft:term(),
                self.cluster.raft:last_index())
        end
    end

    local ac = self.autobalance
    if ac and ac.enabled ~= false then
        if not self.cluster then
            log:warn("autobalance configured without cluster config; ignoring")
        else
            local loop = BalanceLoop.new({
                broker      = self.broker,
                assignments = self.cluster.assignments,
                peers       = self.cluster.peers,
                self_id     = self.cluster.broker_id,
                reassigner  = self.cluster.reassigner,
                fence       = self.cluster.fence,
                raft        = self.cluster.raft,
                interval_s  = ac.interval_s,
                dry_run     = ac.dry_run,
                goals       = ac.goals,
                window      = ac.window,
                min_valid   = ac.min_valid,
                percentile  = ac.percentile,
                max_actions_per_detect = ac.max_actions_per_detect,
            })
            self.balance_loop = loop
            self.reactor:spawn(function()
                loop:run(self.reactor, function() return self.running end)
            end)
            log:info("autobalance: interval=%ss dry_run=%s",
                tostring(loop.interval_s), tostring(loop.dry_run))
        end
    end

    local rc = self.replication
    if rc and rc.enabled then
        local role = rc.role or "leader"
        if role == "follower" or role == "both" then
            local rs = ReplicaServer.new({
                reactor = self.reactor,
                broker  = self.broker,
                host    = rc.replicate_host or "127.0.0.1",
                port    = rc.replicate_port,
                tls     = rc.server_tls,
            })
            rs:start()
        end
        if self.replicator then
            log:info("replication: leader id=%s followers=%d ack_timeout=%ss",
                tostring(rc.replica_id or 1), #self.replicator.followers,
                tostring(self.replicator.ack_timeout))
        end
    end

    self.reactor:run()
    self.running = false

    self.broker:detach_committers()

    log:info("reactor stopped, closing sockets")
    self.reactor:shutdown()

    return true
end

function Server:stop()
    for _, conn in pairs(self.connections_by_id) do
        conn:close(Connection.REASON_SERVER_SHUTDOWN,
            proto.ERR_INTERNAL, "server shutting down")
    end
    self.reactor:stop()
end

function Server:snapshot()
    local topics = self.broker:list_topics()
    table.sort(topics)
    local truncated = false
    if #topics > self.max_list_topics then
        local keep = {}
        for i = 1, self.max_list_topics do keep[i] = topics[i] end
        topics = keep
        truncated = true
    end

    local topic_summaries = {}
    local with_bytes = {}
    for _, name in ipairs(topics) do
        local t = self.broker.topic_manager.topics[name]
        if t then
            local parts = t.partitions or {}
            local total_bytes = 0
            local total_segments = 0
            for _, p in ipairs(parts) do
                total_bytes = total_bytes + (p.offset or 0)
                total_segments = total_segments + (p.segments and #p.segments or 0)
            end
            topic_summaries[#topic_summaries + 1] = {
                name           = name,
                partitions     = #parts,
                bytes_on_disk  = total_bytes,
                segment_count  = total_segments,
            }
            with_bytes[#with_bytes + 1] = topic_summaries[#topic_summaries]
        end
    end

    table.sort(with_bytes, function(a, b)
        return a.bytes_on_disk > b.bytes_on_disk
    end)
    local top_n = {}
    for i = 1, math.min(10, #with_bytes) do top_n[i] = with_bytes[i] end

    return {
        server = {
            name     = proto.SERVER_NAME,
            version  = proto.SERVER_VERSION,
            protocol = proto.PROTOCOL_VERSION,
            host     = self.host,
            port     = self.port,
        },
        connections = {
            open       = self.connections,
            max        = self.max_connections,
            max_per_ip = self.max_connections_per_ip,
        },
        topics = {
            count            = #self.broker:list_topics(),
            max              = self.max_topics,
            listed           = #topic_summaries,
            listed_truncated = truncated,
            top_by_bytes     = top_n,
        },
    }
end

return Server
