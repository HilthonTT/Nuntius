local socket  = require("socket")
local json    = require("dkjson")
local rpc     = require("src.cluster.raft.rpc")
local Node    = require("src.cluster.raft.node")
local metrics = require("src.metrics")
local log     = require("src.log.logger").get("raft")

local DEFAULT_HEARTBEAT_S   = 0.5
local DEFAULT_RPC_TIMEOUT_S = 1.0
local DEFAULT_MAX_BATCH     = 64
local DEFAULT_COMMIT_WAIT_S = 10

local Service = {}
Service.__index = Service

function Service.new(opts)
    local node = assert(opts.node, "node required")
    return setmetatable({
        node        = node,
        reactor     = assert(opts.reactor, "reactor required"),
        addresses   = assert(opts.addresses, "addresses required"),
        tokens      = opts.tokens or {},
        token       = opts.token,
        tls         = opts.tls,
        heartbeat_s = opts.heartbeat_s or DEFAULT_HEARTBEAT_S,
        rpc_timeout = opts.rpc_timeout or DEFAULT_RPC_TIMEOUT_S,
        max_batch   = opts.max_batch or DEFAULT_MAX_BATCH,
        commit_wait = opts.commit_wait or DEFAULT_COMMIT_WAIT_S,
        inflight    = {},
        last_ack    = {},
        next_beat   = 0,
        leader_generation = nil,
    }, Service)
end

function Service:_call(peer_id, path, payload)
    local address = self.addresses[peer_id]
    if not address then return nil, "no address configured" end
    return rpc.post(self.reactor, {
        address = address,
        path    = path,
        body    = json.encode(payload),
        token   = self.tokens[peer_id] or self.token,
        tls     = self.tls,
        timeout = self.rpc_timeout,
    })
end

function Service:_observe_term(reply)
    if type(reply.term) == "number" and reply.term > self.node:term() then
        self.node:become_follower(reply.term)
        local ok, err = self.node:persist()
        if not ok then log:error("%s", tostring(err)) end
        return true
    end
    return false
end

function Service:_elect()
    local node = self.node
    local term, generation = node:begin_election()
    if not term then
        log:error("election aborted: %s", tostring(generation))
        return
    end
    metrics.inc("moonmq_raft_elections_total")

    if node:quorum() == 1 then
        node:record_vote(node.id, term, generation)
        return
    end

    local args = {
        term           = term,
        candidate_id   = node.id,
        last_log_index = node:last_index(),
        last_log_term  = node:last_term(),
    }

    for _, peer_id in ipairs(node.peers) do
        self.reactor:spawn(function()
            local reply, err = self:_call(peer_id, "/cluster/raft/vote", args)
            if not reply then
                log:debug("vote request to %s failed: %s", peer_id, tostring(err))
                return
            end
            if self:_observe_term(reply) then return end
            if reply.granted == true then
                node:record_vote(peer_id, term, generation)
            end
        end)
    end
end

function Service:_replicate(peer_id)
    if self.inflight[peer_id] then return end
    local node = self.node
    local next_index = node.next_index[peer_id] or (node:last_index() + 1)

    if next_index <= node.state.base_index then
        self:_send_snapshot(peer_id)
        return
    end

    local prev_index = next_index - 1
    local prev_term  = node:term_at(prev_index)
    if not prev_term then
        self:_send_snapshot(peer_id)
        return
    end

    local args = {
        term           = node:term(),
        leader_id      = node.id,
        prev_log_index = prev_index,
        prev_log_term  = prev_term,
        leader_commit  = node.commit_index,
        entries        = node:slice(next_index, self.max_batch),
    }

    self.inflight[peer_id] = true
    self.reactor:spawn(function()
        local reply, err = self:_call(peer_id, "/cluster/raft/append", args)
        self.inflight[peer_id] = nil
        if not reply then
            log:debug("append to %s failed: %s", peer_id, tostring(err))
            return
        end
        if self:_observe_term(reply) then return end
        if not node:is_leader() or node:term() ~= args.term then return end

        self.last_ack[peer_id] = socket.gettime()
        if reply.success == true then
            local match = tonumber(reply.match_index) or (next_index + #args.entries - 1)
            node.match_index[peer_id] = math.max(node.match_index[peer_id] or 0, match)
            node.next_index[peer_id]  = node.match_index[peer_id] + 1
            node:advance_commit()
        elseif reply.need_snapshot == true then
            self:_send_snapshot(peer_id)
        else
            local hint = tonumber(reply.match_index)
            local back = hint and (hint + 1) or (next_index - 1)
            node.next_index[peer_id] = math.max(node.state.base_index + 1, back)
        end
    end)
end

function Service:_send_snapshot(peer_id)
    if self.inflight[peer_id] then return end
    local node = self.node
    local args = node:snapshot_args()

    self.inflight[peer_id] = true
    self.reactor:spawn(function()
        local reply, err = self:_call(peer_id, "/cluster/raft/snapshot", args)
        self.inflight[peer_id] = nil
        if not reply then
            log:debug("snapshot to %s failed: %s", peer_id, tostring(err))
            return
        end
        if self:_observe_term(reply) then return end
        if not node:is_leader() or node:term() ~= args.term then return end

        self.last_ack[peer_id] = socket.gettime()
        if reply.ok == true then
            node.match_index[peer_id] = math.max(node.match_index[peer_id] or 0,
                args.last_index)
            node.next_index[peer_id] = args.last_index + 1
            node:advance_commit()
        end
    end)
end

function Service:_quorum_contact(now)
    local node = self.node
    local fresh, cutoff = 1, now - node.election_min
    for _, peer_id in ipairs(node.peers) do
        if (self.last_ack[peer_id] or 0) >= cutoff then fresh = fresh + 1 end
    end
    return fresh >= node:quorum()
end

function Service:step()
    local node = self.node
    local now = socket.gettime()

    if node:is_leader() then
        if self.leader_generation ~= node.generation then
            self.leader_generation = node.generation
            self.next_beat = 0
            for _, peer_id in ipairs(node.peers) do self.last_ack[peer_id] = now end
        end
        if now >= self.next_beat then
            self.next_beat = now + self.heartbeat_s
            for _, peer_id in ipairs(node.peers) do self:_replicate(peer_id) end
        end
        if not self:_quorum_contact(now) then
            log:warn("lost contact with a quorum; giving up the controller role")
            node:become_follower(node:term())
        end
    else
        self.leader_generation = nil
        if now >= node.election_deadline then self:_elect() end
    end

    metrics.set("moonmq_raft_term", node:term())
    metrics.set("moonmq_raft_is_controller", node:is_leader() and 1 or 0)
    metrics.set("moonmq_raft_commit_index", node.commit_index)
end

function Service:run(running)
    local tick = math.max(0.05, self.heartbeat_s / 4)
    self.next_beat = 0
    for _, peer_id in ipairs(self.node.peers) do
        self.last_ack[peer_id] = socket.gettime()
    end
    while running() do
        self.reactor:sleep(tick)
        if not running() then return end
        local ok, err = pcall(self.step, self)
        if not ok then log:error("raft tick failed: %s", tostring(err)) end
    end
end

function Service:commit(kind, data)
    local node = self.node
    local index, err = node:propose(kind, data)
    if not index then return nil, err end

    for _, peer_id in ipairs(node.peers) do self:_replicate(peer_id) end

    local deadline = socket.gettime() + self.commit_wait
    while node.last_applied < index do
        if not node:is_leader() then
            return nil, "lost the controller role before the entry committed"
        end
        if socket.gettime() > deadline then
            return nil, string.format(
                "log index %d was not committed within %ds", index, self.commit_wait)
        end
        self.reactor:sleep(0.02)
    end
    return index
end

Service.KIND_CONTROLLER = Node.KIND_CONTROLLER
Service.KIND_OWNER      = Node.KIND_OWNER

return Service
