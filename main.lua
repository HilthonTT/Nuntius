local Server = require("src.server.server")
local Config = require("src.server.config")
local auth_m = require("src.server.auth")
local users_m = require("src.server.users")
local quota_m = require("src.server.quota")
local tls_m = require("src.io.tls")
local version_m = require("src.core.version")
local Log    = require("src.log.logger")
local repl = require("src.repl.repl")

local log = Log.get("main")

local function is_main(argv, ...)
    local n_arg = argv and #argv or 0
    if n_arg == select("#", ...) then
        for i = 1, n_arg do
            if argv[i] ~= select(i, ...) then return false end
        end
        return true
    end
    return false
end

local function run_cli_command(argv)
    local cmd = argv and argv[1]

    if cmd == "--repl" then
        repl()
        return true
    end

    if cmd == "version" or cmd == "--version" or cmd == "-v" then
        local sub = argv[2]
        if sub == "--json" then
            print(version_m.GetVersionJSON())
        elseif sub == "--short" then
            print(version_m.GetVersionInfo():Short())
        else
            print(version_m.GetVersionInfo():String())
        end
        return true
    end
    return false
end

local function build_auth(cfg)
    local ac = cfg.Auth or {}

    if ac.Password == "CHANGE_ME" then
        log:warn("default password in use; replace Auth.Password")
    end

    local store, serr = users_m.load(ac)
    if serr then
        log:error("Auth config: %s", serr)
        os.exit(1)
    end
    if not store then
        log:warn("no credentials configured, server is OPEN "
            .. "(any client may produce, consume, and delete any topic)")
        return nil, nil
    end

    local authenticator = auth_m.authenticator({
        store          = store,
        max_failures   = ac.MaxFailures,
        failure_window = ac.FailureWindow,
        ban_duration   = ac.BanDuration,
    })
    log:info("auth: %d user(s): %s", store:count(), store:describe())

    local qc = ac.Quotas or {}
    local default_spec, derr = quota_m.spec(qc.Default)
    if derr then
        log:error("Auth.Quotas.Default: %s", derr)
        os.exit(1)
    end

    local topic_specs = {}
    for name, block in pairs(qc.Topics or {}) do
        local spec, terr = quota_m.spec(block)
        if terr then
            log:error("Auth.Quotas.Topics.%s: %s", name, terr)
            os.exit(1)
        end
        topic_specs[name] = spec
    end

    local user_specs = store:quota_specs()

    local quotas
    if default_spec or next(topic_specs) ~= nil or next(user_specs) ~= nil then
        quotas = quota_m.new({
            default       = default_spec,
            users         = user_specs,
            topics        = topic_specs,
            burst_seconds = qc.BurstSeconds,
        })
        local n_users, n_topics = 0, 0
        for _ in pairs(user_specs)  do n_users  = n_users  + 1 end
        for _ in pairs(topic_specs) do n_topics = n_topics + 1 end
        log:info("quotas enabled (default=%s, %d user override(s), %d topic rule(s))",
            default_spec and "yes" or "no", n_users, n_topics)
    end

    return authenticator, quotas
end

local function build_tls(block, where, mode)
    local server_cfg, client_cfg

    if mode ~= "client" then
        local cfg, err = tls_m.server_config(block, where)
        if err then
            log:error("%s", err)
            os.exit(1)
        end
        server_cfg = cfg
    end

    if mode ~= "server" then
        local cfg, err = tls_m.client_config(block, where)
        if err then
            log:error("%s", err)
            os.exit(1)
        end
        client_cfg = cfg
    end

    if server_cfg or client_cfg then
        local ok, err = tls_m.require_available(where)
        if not ok then
            log:error("%s", err)
            os.exit(1)
        end
    end

    return tls_m.register(server_cfg), tls_m.register(client_cfg)
end

local function build_metrics_auth(cfg)
    local mc = Config.get(cfg, "Server.MetricsAuth", nil)
    local token = os.getenv("MOONMQ_METRICS_TOKEN")
    if type(mc) ~= "table" and not token then return nil end
    mc = type(mc) == "table" and mc or {}

    if mc.Token and mc.Token ~= "" then token = mc.Token end
    local basic = mc.Basic == true

    if not token and not basic then return nil end
    return { token = token, basic = basic }
end

if is_main(arg, ...) then
    if run_cli_command(arg) then
        os.exit(0)
    end

    local cfg, cerr = Config.load()
    if not cfg then
        log:error("config: %s", cerr)
        os.exit(1)
    end

    local log_file = Config.get(cfg, "Logging.File", "")
    if log_file == "" then log_file = nil end
    Log.configure({
        level         = Config.get(cfg, "Logging.Level", "INFO"),
        file_path     = log_file,
        log_to_stderr = Config.get(cfg, "Logging.LogToStderr", true),
    })

    local s = cfg.Server or {}
    local gc = s.GroupCommit or {}

    local authenticator, quotas = build_auth(cfg)

    local rep = s.Replication or {}
    local peers = {}
    for _, p in ipairs(rep.Peers or {}) do
        peers[#peers + 1] = { id = p.Id, address = p.Address }
    end
    local rep_server_tls, rep_client_tls = build_tls(rep.Tls, "Replication.Tls")
    local replication = {
        enabled        = rep.Enabled or false,
        replica_id     = rep.ReplicaId or 1,
        role           = rep.Role or "leader",
        replicate_host = rep.ReplicateHost or "127.0.0.1",
        replicate_port = rep.ReplicatePort,
        peers          = peers,
        lag_max        = rep.LagMax,
        ack_timeout    = rep.AckTimeout,
        server_tls     = rep_server_tls,
        tls            = rep_client_tls,
    }

    local cluster = nil
    local cl = s.Cluster
    if cl and cl.Enabled ~= false and cl.BrokerId then
        local cluster_peers = {}
        for _, p in ipairs(cl.Peers or {}) do
            cluster_peers[#cluster_peers + 1] =
                { id = p.Id, address = p.Address, token = p.Token }
        end
        local cl_server_tls, cl_client_tls = build_tls(cl.Tls, "Cluster.Tls")
        cluster = {
            broker_id    = cl.BrokerId,
            host         = cl.Host or "127.0.0.1",
            port         = cl.Port,
            peers        = cluster_peers,
            token        = cl.Token,
            peer_timeout = cl.PeerTimeout,
            batch_bytes  = cl.BatchBytes,
            server_tls   = cl_server_tls,
            tls          = cl_client_tls,
        }
    end

    local autobalance = nil
    local ab = s.Autobalance
    if ab and ab.Enabled ~= false and cluster then
        autobalance = {
            interval_s             = ab.IntervalSeconds,
            dry_run                = ab.DryRun,
            window                 = ab.Window,
            min_valid              = ab.MinValid,
            percentile             = ab.Percentile,
            max_actions_per_detect = ab.MaxActionsPerDetect,
        }
    end

    local srv = assert(Server.new({
        acks                   = s.Acks,
        replication            = replication,
        cluster                = cluster,
        autobalance            = autobalance,
        dlq                    = s.Dlq and {
            suffix         = s.Dlq.Suffix,
            max_deliveries = s.Dlq.MaxDeliveries,
        } or nil,
        data_dir               = s.DataDir or "./data_server",
        default_backend        = s.StorageBackend,
        host                   = s.Host or "0.0.0.0",
        port                   = s.Port or 9092,
        max_connections        = s.MaxConnections,
        max_connections_per_ip = s.MaxConnectionsPerIP,
        fd_reserve             = s.FdReserve,
        max_frame              = s.MaxFrameSize,
        max_pending_bytes      = s.MaxPendingBytes,
        send_deadline          = s.SendDeadline,
        idle_deadline          = s.IdleDeadline,
        pre_auth_read_deadline = s.PreAuthReadDeadline,
        handshake_deadline     = s.HandshakeDeadline,
        heartbeat_interval       = s.HeartbeatInterval,
        heartbeat_miss_threshold = s.HeartbeatMissThreshold,
        max_topics             = s.MaxTopics,
        max_list_topics        = s.MaxListTopics,
        producer_expiry_s              = s.ProducerExpirySeconds,
        producer_expiry_check_interval = s.ProducerExpiryCheckIntervalSeconds,
        metrics_host           = s.MetricsHost or "127.0.0.1",
        metrics_port           = s.MetricsPort or 9090,
        authenticator          = authenticator,
        quotas                 = quotas,
        metrics_auth           = build_metrics_auth(cfg),
        tls                    = (build_tls(s.Tls, "Server.Tls", "server")),
        metrics_tls            = (build_tls(s.MetricsTls, "Server.MetricsTls", "server")),
        group_commit_linger_s    = gc.LingerMs and gc.LingerMs / 1000 or nil,
        group_commit_max_waiters = gc.MaxWaiters,
    }))

    log:info("env=%s host=%s port=%d data_dir=%s",
        cfg._environment, srv.host, srv.port, s.DataDir or "./data_server")
    srv:start()
end