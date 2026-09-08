local socket = require("socket")
local log    = require("src.log.logger").get("raft")

local Node = {}
Node.__index = Node

Node.FOLLOWER  = "follower"
Node.CANDIDATE = "candidate"
Node.LEADER    = "leader"

Node.KIND_CONTROLLER = "controller"
Node.KIND_OWNER      = "owner"

local DEFAULT_ELECTION_MIN    = 2.5
local DEFAULT_ELECTION_MAX    = 4.0
local DEFAULT_MAX_LOG_ENTRIES = 512

function Node.new(opts)
    assert(type(opts) == "table", "opts must be a table")
    local store = assert(opts.store, "store required")
    local state = assert(store.state, "store has no state")

    local peers = {}
    for _, id in ipairs(opts.peers or {}) do
        if id ~= opts.id then peers[#peers + 1] = id end
    end

    local self = setmetatable({
        id              = assert(opts.id, "id required"),
        peers           = peers,
        store           = store,
        state           = state,
        role            = Node.FOLLOWER,
        leader_id       = nil,
        commit_index    = state.base_index,
        last_applied    = state.base_index,
        next_index      = {},
        match_index     = {},
        votes           = {},
        generation      = 0,
        election_min    = opts.election_min or DEFAULT_ELECTION_MIN,
        election_max    = opts.election_max or DEFAULT_ELECTION_MAX,
        max_log_entries = opts.max_log_entries or DEFAULT_MAX_LOG_ENTRIES,
        apply_fn        = opts.apply,
        snapshot_fn     = opts.snapshot,
        restore_fn      = opts.restore,
        now             = opts.now or socket.gettime,
        random          = opts.random or math.random,
        election_deadline = 0,
    }, Node)

    if state.snapshot and self.restore_fn then
        self.restore_fn(state.snapshot)
    end
    self:reset_election_timer()
    return self
end

function Node:size()
    return #self.peers + 1
end

function Node:quorum()
    return math.floor(self:size() / 2) + 1
end

function Node:last_index()
    local entries = self.state.entries
    local n = #entries
    if n == 0 then return self.state.base_index end
    return entries[n].index
end

function Node:last_term()
    local entries = self.state.entries
    local n = #entries
    if n == 0 then return self.state.base_term end
    return entries[n].term
end

function Node:entry_at(index)
    local pos = index - self.state.base_index
    if pos < 1 then return nil end
    return self.state.entries[pos]
end

function Node:term_at(index)
    if index == self.state.base_index then return self.state.base_term end
    local entry = self:entry_at(index)
    return entry and entry.term or nil
end

function Node:slice(from, max)
    local out = {}
    local index = from
    while #out < max do
        local entry = self:entry_at(index)
        if not entry then break end
        out[#out + 1] = entry
        index = index + 1
    end
    return out
end

function Node:truncate_from(index)
    local pos = index - self.state.base_index
    if pos < 1 then pos = 1 end
    local entries = self.state.entries
    for i = #entries, pos, -1 do entries[i] = nil end
end

function Node:persist()
    local ok, err = self.store:save(self.state)
    if not ok then
        return nil, string.format("persist raft state: %s", tostring(err))
    end
    return true
end

function Node:reset_election_timer()
    local span = self.election_max - self.election_min
    self.election_deadline = self.now() + self.election_min + self.random() * span
end

function Node:is_leader()
    return self.role == Node.LEADER
end

function Node:term()
    return self.state.current_term
end

function Node:become_follower(term, leader_id)
    if term > self.state.current_term then
        self.state.current_term = term
        self.state.voted_for = nil
    end
    if self.role == Node.LEADER then
        log:info("stepping down to follower at term %d", self.state.current_term)
    end
    self.role = Node.FOLLOWER
    self.leader_id = leader_id
    self.generation = self.generation + 1
    self.next_index = {}
    self.match_index = {}
    self:reset_election_timer()
end

function Node:begin_election()
    local prev_term, prev_vote = self.state.current_term, self.state.voted_for
    self.state.current_term = self.state.current_term + 1
    self.state.voted_for = self.id

    local ok, err = self:persist()
    if not ok then
        self.state.current_term, self.state.voted_for = prev_term, prev_vote
        return nil, err
    end

    self.role = Node.CANDIDATE
    self.leader_id = nil
    self.votes = { [self.id] = true }
    self.generation = self.generation + 1
    self:reset_election_timer()
    log:info("starting an election for term %d", self.state.current_term)
    return self.state.current_term, self.generation
end

function Node:record_vote(voter, term, generation)
    if self.role ~= Node.CANDIDATE then return false end
    if generation ~= self.generation then return false end
    if term ~= self.state.current_term then return false end

    self.votes[voter] = true
    local count = 0
    for _ in pairs(self.votes) do count = count + 1 end
    if count < self:quorum() then return false end
    return self:become_leader()
end

function Node:become_leader()
    self.role = Node.LEADER
    self.leader_id = self.id
    self.generation = self.generation + 1
    self.next_index = {}
    self.match_index = {}
    local next_idx = self:last_index() + 1
    for _, id in ipairs(self.peers) do
        self.next_index[id] = next_idx
        self.match_index[id] = 0
    end
    log:info("elected controller for term %d", self.state.current_term)

    local _, err = self:propose(Node.KIND_CONTROLLER, {
        leader = self.id, term = self.state.current_term,
    })
    if err then
        log:error("could not record the controller claim: %s", tostring(err))
        self:become_follower(self.state.current_term)
        return false
    end
    return true
end

function Node:propose(kind, data)
    if self.role ~= Node.LEADER then return nil, "not the raft controller" end
    local entry = {
        term  = self.state.current_term,
        index = self:last_index() + 1,
        kind  = kind,
        data  = data or {},
    }
    self.state.entries[#self.state.entries + 1] = entry

    local ok, err = self:persist()
    if not ok then
        self.state.entries[#self.state.entries] = nil
        return nil, err
    end
    self:advance_commit()
    return entry.index
end

function Node:advance_commit()
    if self.role ~= Node.LEADER then return end
    local quorum = self:quorum()
    for index = self:last_index(), self.commit_index + 1, -1 do
        if self:term_at(index) == self.state.current_term then
            local count = 1
            for _, id in ipairs(self.peers) do
                if (self.match_index[id] or 0) >= index then count = count + 1 end
            end
            if count >= quorum then
                self.commit_index = index
                break
            end
        end
    end
    self:apply_committed()
end

function Node:apply_committed()
    while self.last_applied < self.commit_index do
        local next_index = self.last_applied + 1
        local entry = self:entry_at(next_index)
        if not entry then break end
        if self.apply_fn then
            local ok, err = self.apply_fn(entry)
            if not ok then
                log:error("applying log index %d (%s) failed: %s; will retry",
                    entry.index, entry.kind, tostring(err))
                return
            end
        end
        self.last_applied = next_index
    end
    self:maybe_compact()
end

function Node:maybe_compact()
    if not self.snapshot_fn then return end
    if #self.state.entries <= self.max_log_entries then return end
    if self.last_applied <= self.state.base_index then return end

    local base_term = self:term_at(self.last_applied)
    if not base_term then return end

    local kept, index = {}, self.last_applied + 1
    while true do
        local entry = self:entry_at(index)
        if not entry then break end
        kept[#kept + 1] = entry
        index = index + 1
    end

    local prev = {
        entries    = self.state.entries,
        base_index = self.state.base_index,
        base_term  = self.state.base_term,
        snapshot   = self.state.snapshot,
    }
    self.state.entries    = kept
    self.state.base_index = self.last_applied
    self.state.base_term  = base_term
    self.state.snapshot   = self.snapshot_fn()

    local ok, err = self:persist()
    if not ok then
        self.state.entries    = prev.entries
        self.state.base_index = prev.base_index
        self.state.base_term  = prev.base_term
        self.state.snapshot   = prev.snapshot
        log:error("log compaction rolled back: %s", tostring(err))
        return
    end
    log:info("compacted the controller log up to index %d", self.state.base_index)
end

function Node:snapshot_args()
    local state = self.state.snapshot
    if not state and self.snapshot_fn then state = self.snapshot_fn() end
    return {
        term       = self.state.current_term,
        leader_id  = self.id,
        last_index = self.state.base_index,
        last_term  = self.state.base_term,
        state      = state or {},
    }
end

function Node:handle_vote(args)
    if type(args) ~= "table" or type(args.term) ~= "number"
       or type(args.candidate_id) ~= "string"
       or type(args.last_log_index) ~= "number"
       or type(args.last_log_term) ~= "number" then
        return nil, "vote: need {term, candidate_id, last_log_index, last_log_term}"
    end

    if args.term < self.state.current_term then
        return { term = self.state.current_term, granted = false }
    end
    if args.term > self.state.current_term then
        self:become_follower(args.term)
        local ok, err = self:persist()
        if not ok then return nil, err end
    end

    local voted_for = self.state.voted_for
    local last_term, last_index = self:last_term(), self:last_index()
    local up_to_date = args.last_log_term > last_term
        or (args.last_log_term == last_term and args.last_log_index >= last_index)

    if (voted_for == nil or voted_for == args.candidate_id) and up_to_date then
        self.state.voted_for = args.candidate_id
        local ok, err = self:persist()
        if not ok then
            self.state.voted_for = voted_for
            return nil, err
        end
        self:reset_election_timer()
        return { term = self.state.current_term, granted = true }
    end

    return { term = self.state.current_term, granted = false }
end

function Node:handle_append(args)
    if type(args) ~= "table" or type(args.term) ~= "number"
       or type(args.leader_id) ~= "string"
       or type(args.prev_log_index) ~= "number"
       or type(args.prev_log_term) ~= "number"
       or type(args.leader_commit) ~= "number"
       or type(args.entries) ~= "table" then
        return nil, "append: need {term, leader_id, prev_log_index, prev_log_term, "
            .. "leader_commit, entries}"
    end

    if args.term < self.state.current_term then
        return { term = self.state.current_term, success = false }
    end

    local before_term = self.state.current_term
    self:become_follower(args.term, args.leader_id)
    if self.state.current_term ~= before_term then
        local ok, err = self:persist()
        if not ok then return nil, err end
    end

    if args.prev_log_index < self.state.base_index then
        return { term = self.state.current_term, success = false, need_snapshot = true }
    end
    if args.prev_log_index > self:last_index() then
        return { term = self.state.current_term, success = false,
                 match_index = self:last_index() }
    end
    if self:term_at(args.prev_log_index) ~= args.prev_log_term then
        self:truncate_from(args.prev_log_index)
        local ok, err = self:persist()
        if not ok then return nil, err end
        return { term = self.state.current_term, success = false,
                 match_index = math.max(self.state.base_index, args.prev_log_index - 1) }
    end

    local dirty = false
    for i, raw in ipairs(args.entries) do
        if type(raw) ~= "table" or type(raw.term) ~= "number"
           or type(raw.kind) ~= "string" then
            return nil, "append: malformed log entry"
        end
        local index = args.prev_log_index + i
        local entry = {
            term  = raw.term,
            index = index,
            kind  = raw.kind,
            data  = type(raw.data) == "table" and raw.data or {},
        }
        local existing = self:term_at(index)
        if existing == nil then
            self.state.entries[index - self.state.base_index] = entry
            dirty = true
        elseif existing ~= entry.term then
            self:truncate_from(index)
            self.state.entries[index - self.state.base_index] = entry
            dirty = true
        end
    end

    if args.leader_commit > self.commit_index then
        self.commit_index = math.min(args.leader_commit, self:last_index())
    end

    if dirty then
        local ok, err = self:persist()
        if not ok then return nil, err end
    end
    self:apply_committed()

    return { term = self.state.current_term, success = true,
             match_index = self:last_index() }
end

function Node:handle_snapshot(args)
    if type(args) ~= "table" or type(args.term) ~= "number"
       or type(args.leader_id) ~= "string"
       or type(args.last_index) ~= "number"
       or type(args.last_term) ~= "number"
       or type(args.state) ~= "table" then
        return nil, "snapshot: need {term, leader_id, last_index, last_term, state}"
    end

    if args.term < self.state.current_term then
        return { term = self.state.current_term, ok = false }
    end
    local before_term = self.state.current_term
    self:become_follower(args.term, args.leader_id)

    if args.last_index <= self.state.base_index then
        if self.state.current_term ~= before_term then
            local ok, err = self:persist()
            if not ok then return nil, err end
        end
        return { term = self.state.current_term, ok = true }
    end

    local prev = {
        entries    = self.state.entries,
        base_index = self.state.base_index,
        base_term  = self.state.base_term,
        snapshot   = self.state.snapshot,
    }
    self.state.entries    = {}
    self.state.base_index = args.last_index
    self.state.base_term  = args.last_term
    self.state.snapshot   = args.state

    local ok, err = self:persist()
    if not ok then
        self.state.entries    = prev.entries
        self.state.base_index = prev.base_index
        self.state.base_term  = prev.base_term
        self.state.snapshot   = prev.snapshot
        return nil, err
    end

    if self.restore_fn then self.restore_fn(args.state) end
    self.commit_index = math.max(self.commit_index, args.last_index)
    self.last_applied = args.last_index
    log:info("installed a controller snapshot up to index %d", args.last_index)
    return { term = self.state.current_term, ok = true }
end

return Node
