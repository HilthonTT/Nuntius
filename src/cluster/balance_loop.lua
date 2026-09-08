local socket       = require("socket")
local Autobalancer = require("src.autobalancer")
local Resource     = require("src.autobalancer.common.resource")
local Topic        = require("src.storage.topic")
local local_loads  = require("src.cluster.local_loads")
local log          = require("src.log.logger").get("balance_loop")

local DEFAULT_INTERVAL_S = 60

local BalanceLoop = {}
BalanceLoop.__index = BalanceLoop

function BalanceLoop.new(opts)
    local self = setmetatable({
        broker      = assert(opts.broker, "broker required"),
        assignments = assert(opts.assignments, "assignments required"),
        peers       = assert(opts.peers, "peers required"),
        self_id     = assert(opts.self_id, "self_id required"),
        reassigner  = opts.reassigner,
        interval_s  = opts.interval_s or DEFAULT_INTERVAL_S,
        dry_run     = opts.dry_run or false,
        fence       = opts.fence,
        raft        = opts.raft,
        controller_epoch = nil,
        fenced      = false,
        topic_refs  = {},
        prev_totals = {},
    }, BalanceLoop)

    local goals = opts.goals or {}

    self.ab = Autobalancer.new({
        goals                  = goals,
        window                 = opts.window,
        min_valid              = opts.min_valid or 1,
        percentile             = opts.percentile,
        max_actions_per_detect = opts.max_actions_per_detect,
        emit_metrics           = opts.emit_metrics,
        execute                = (not self.dry_run and self.reassigner) and function(actions)
            return self.reassigner:execute(actions)
        end or nil,
    })
    return self
end

function BalanceLoop:_topic_ref(name)
    local t = self.topic_refs[name]
    if not t then
        t = Topic.new(name)
        self.topic_refs[name] = t
    end
    return t
end

function BalanceLoop:_feed_broker(broker_id, loads, seen)
    self.ab.model:register_broker(broker_id)
    local now = socket.gettime()
    for _, l in ipairs(loads) do
        if type(l.topic) == "string" and type(l.partition) == "number" then
            local topic = self:_topic_ref(l.topic)
            self.ab.model:register_replica(broker_id, topic, l.partition)
            self.ab.model:update_replica_load(broker_id, l.topic, l.partition,
                Resource.DISK, tonumber(l.disk_bytes) or 0)
            local skey = broker_id .. "\0" .. l.topic .. "\0" .. l.partition
            seen[skey] = true

            local bin, bout = tonumber(l.bytes_in_total), tonumber(l.bytes_out_total)
            if bin ~= nil and bout ~= nil then
                local prev = self.prev_totals[skey]
                if prev and now > prev.at and bin >= prev.bin and bout >= prev.bout then
                    local dt = now - prev.at
                    self.ab.model:update_replica_load(broker_id, l.topic, l.partition,
                        Resource.NW_IN, (bin - prev.bin) / dt)
                    self.ab.model:update_replica_load(broker_id, l.topic, l.partition,
                        Resource.NW_OUT, (bout - prev.bout) / dt)
                end
                self.prev_totals[skey] = { at = now, bin = bin, bout = bout }
            end
        end
    end
end

function BalanceLoop:_local_loads()
    return local_loads.collect(self.broker, self.assignments)
end

function BalanceLoop:_prune(seen)
    local model = self.ab.model
    for broker_id, bucket in pairs(model.replicas) do
        for key, updater in pairs(bucket) do
            local skey = broker_id .. "\0" .. updater.topic.name .. "\0" .. updater.partition
            if not seen[skey] then
                bucket[key] = nil
            end
        end
    end
    for skey in pairs(self.prev_totals) do
        if not seen[skey] then self.prev_totals[skey] = nil end
    end
end

function BalanceLoop:_announce_controller(epoch)
    if self.controller_epoch == epoch then return end
    self.controller_epoch = epoch
    for _, peer in pairs(self.peers) do
        if peer.set_controller then peer:set_controller(epoch, self.self_id) end
    end
    log:info("acting as controller for epoch %d", epoch)
end

function BalanceLoop:_ensure_controller()
    if self.raft then
        if not self.raft:is_leader() then
            if self.controller_epoch then
                self.controller_epoch = nil
                for _, peer in pairs(self.peers) do
                    if peer.set_controller then peer:set_controller(nil) end
                end
            end
            return nil, "not the raft controller; not acting"
        end
        self:_announce_controller(self.raft:term())
        return true
    end

    if not self.fence then return true end
    if self.fenced then return nil, "controller superseded; not acting" end

    if not self.controller_epoch then
        local epoch, cerr = self.fence:claim(self.self_id)
        if not epoch then return nil, cerr end
        self:_announce_controller(epoch)
    end

    for id, peer in pairs(self.peers) do
        if peer.claim_controller then
            local accepted, highest, reason =
                peer:claim_controller(self.controller_epoch, self.self_id)
            if accepted == false then
                self.fenced = true
                for _, p in pairs(self.peers) do
                    if p.set_controller then p:set_controller(nil) end
                end
                log:error("fenced: peer %s holds controller epoch %s (%s); "
                    .. "this balance loop stops acting",
                    id, tostring(highest), tostring(reason))
                return nil, "controller superseded; not acting"
            end
        end
    end
    return true
end

function BalanceLoop:tick()
    local cok, cerr = self:_ensure_controller()
    if not cok then return {}, cerr end

    local seen = {}
    self:_feed_broker(self.self_id, self:_local_loads(), seen)

    for id, peer in pairs(self.peers) do
        local loads, err = peer:loads()
        if loads then
            self.ab.model:register_broker(id, { active = true })
            self:_feed_broker(id, loads, seen)
        else
            log:warn("peer %s unreachable, excluded from this pass: %s", id, err)
            self.ab.model:register_broker(id)
            self.ab.model:set_broker_active(id, false)
        end
    end

    self:_prune(seen)

    local actions, err = self.ab:run_once()
    if self.dry_run and #actions > 0 then
        for _, a in ipairs(actions) do log:info("dry-run plan: %s", a:pretty()) end
    end
    return actions, err
end

function BalanceLoop:run(reactor, running)
    while running() do
        reactor:sleep(self.interval_s)
        if not running() then return end
        local ok, err = pcall(self.tick, self)
        if not ok then
            log:error("balance tick failed: %s", tostring(err))
        end
    end
end

return BalanceLoop
