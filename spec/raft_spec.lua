local os_utils = require("src.core.os")
local Store    = require("src.cluster.raft.store")
local Node     = require("src.cluster.raft.node")
local Fence    = require("src.cluster.raft.fence")

local BASE = os_utils.IS_WINDOWS and "C:\\Temp\\moonmq_raft_test"
    or "/tmp/moonmq_raft_test"

local function rmdir(path)
    if os_utils.IS_WINDOWS then
        os.execute(string.format('rmdir /s /q "%s" 2>nul', path:gsub("/", "\\")))
    else
        os.execute(string.format("rm -rf '%s'", path))
    end
end

local function mkdir(path)
    if os_utils.IS_WINDOWS then
        os.execute(string.format('mkdir "%s" 2>nul', path:gsub("/", "\\")))
    else
        os.execute(string.format("mkdir -p '%s'", path))
    end
end

local function memory_store()
    return {
        state = Store.empty_state(),
        saves = 0,
        save = function(self, state)
            self.state = state
            self.saves = self.saves + 1
            return true
        end,
    }
end

local function make_node(id, peers, opts)
    opts = opts or {}
    local applied = {}
    local owners = {}
    local node = Node.new({
        id    = id,
        peers = peers,
        store = opts.store or memory_store(),
        now   = opts.now,
        random = function() return 0 end,
        max_log_entries = opts.max_log_entries,
        apply = function(entry)
            applied[#applied + 1] = entry
            if entry.kind == Node.KIND_OWNER then
                owners[entry.data.topic .. "/" .. entry.data.partition] = entry.data.owner
            end
            return true
        end,
        snapshot = function()
            local out = {}
            for k, v in pairs(owners) do out[#out + 1] = { key = k, owner = v } end
            table.sort(out, function(a, b) return a.key < b.key end)
            return { owners = out }
        end,
        restore = function(state)
            owners = {}
            for _, e in ipairs((state or {}).owners or {}) do
                owners[e.key] = e.owner
            end
            return true
        end,
    })
    return node, applied, function() return owners end
end

describe("raft store", function()

    before_each(function() rmdir(BASE); mkdir(BASE) end)
    after_each(function() rmdir(BASE) end)

    it("starts empty and round-trips term, vote and entries", function()
        local store = assert(Store.new(BASE))
        assert.are.equal(0, store.state.current_term)
        assert.is_nil(store.state.voted_for)

        store.state.current_term = 4
        store.state.voted_for    = "b2"
        store.state.entries[1]   = {
            term = 4, index = 1, kind = "owner",
            data = { topic = "orders", partition = 1, owner = "b2" },
        }
        assert(store:save(store.state))

        local reloaded = assert(Store.new(BASE))
        assert.are.equal(4, reloaded.state.current_term)
        assert.are.equal("b2", reloaded.state.voted_for)
        assert.are.equal(1, #reloaded.state.entries)
        assert.are.equal("orders", reloaded.state.entries[1].data.topic)
    end)

    it("refuses a log whose indexes do not start at base_index + 1", function()
        local store = assert(Store.new(BASE))
        store.state.entries[1] = { term = 1, index = 7, kind = "controller", data = {} }
        assert(store:save(store.state))
        local reloaded, err = Store.new(BASE)
        assert.is_nil(reloaded)
        assert.is_truthy(err:find("malformed"))
    end)
end)

describe("raft elections", function()

    it("a lone member elects itself and commits its controller claim", function()
        local node, applied = make_node("b1", { "b1" })
        local term, generation = node:begin_election()
        assert.are.equal(1, term)
        assert.is_true(node:record_vote("b1", term, generation))
        assert.is_true(node:is_leader())
        assert.are.equal(1, #applied)
        assert.are.equal(Node.KIND_CONTROLLER, applied[1].kind)
    end)

    it("needs a majority before it becomes the controller", function()
        local node = make_node("b1", { "b1", "b2", "b3" })
        local term, generation = node:begin_election()
        assert.is_false(node:record_vote("b1", term, generation))
        assert.is_false(node:is_leader())
        assert.is_true(node:record_vote("b2", term, generation))
        assert.is_true(node:is_leader())
    end)

    it("ignores votes from a superseded election", function()
        local node = make_node("b1", { "b1", "b2", "b3" })
        local term, generation = node:begin_election()
        node:begin_election()
        assert.is_false(node:record_vote("b2", term, generation))
        assert.is_false(node:is_leader())
    end)

    it("grants one vote per term and refuses the second candidate", function()
        local node = make_node("b1", { "b1", "b2", "b3" })
        local first = assert(node:handle_vote({
            term = 2, candidate_id = "b2", last_log_index = 0, last_log_term = 0,
        }))
        assert.is_true(first.granted)

        local second = assert(node:handle_vote({
            term = 2, candidate_id = "b3", last_log_index = 0, last_log_term = 0,
        }))
        assert.is_false(second.granted)
        assert.are.equal(2, second.term)
    end)

    it("refuses a candidate whose log is behind", function()
        local node = make_node("b1", { "b1", "b2" })
        node.state.current_term = 3
        node.state.entries[1] = { term = 3, index = 1, kind = "controller", data = {} }

        local reply = assert(node:handle_vote({
            term = 4, candidate_id = "b2", last_log_index = 0, last_log_term = 0,
        }))
        assert.is_false(reply.granted)
    end)

    it("steps down when it sees a higher term", function()
        local node = make_node("b1", { "b1" })
        local term, generation = node:begin_election()
        node:record_vote("b1", term, generation)
        assert.is_true(node:is_leader())

        node:handle_append({
            term = 9, leader_id = "b2", prev_log_index = 0, prev_log_term = 0,
            leader_commit = 0, entries = {},
        })
        assert.is_false(node:is_leader())
        assert.are.equal(9, node:term())
        assert.are.equal("b2", node.leader_id)
    end)
end)

describe("raft log replication", function()

    local function leader_of(peers)
        local node, applied, owners = make_node("b1", peers)
        local term, generation = node:begin_election()
        for _, id in ipairs(peers) do
            if id ~= "b1" then node:record_vote(id, term, generation) end
        end
        node:record_vote("b1", term, generation)
        assert.is_true(node:is_leader())
        return node, applied, owners
    end

    it("commits an ownership change once a majority has it", function()
        local node, _, owners = leader_of({ "b1", "b2", "b3" })
        local index = assert(node:propose(Node.KIND_OWNER,
            { topic = "orders", partition = 1, owner = "b2" }))

        assert.are.equal(nil, owners()["orders/1"])
        node.match_index["b2"] = index
        node:advance_commit()
        assert.are.equal("b2", owners()["orders/1"])
    end)

    it("refuses a proposal from a broker that is not the controller", function()
        local node = make_node("b1", { "b1", "b2" })
        local index, err = node:propose(Node.KIND_OWNER, { topic = "t", partition = 1 })
        assert.is_nil(index)
        assert.is_truthy(err:find("controller"))
    end)

    it("rejects an append whose previous entry does not match, then converges", function()
        local follower = make_node("b2", { "b1", "b2", "b3" })
        assert(follower:handle_append({
            term = 1, leader_id = "b1", prev_log_index = 0, prev_log_term = 0,
            leader_commit = 0,
            entries = { { term = 1, kind = "controller", data = {} } },
        }))

        local mismatch = assert(follower:handle_append({
            term = 2, leader_id = "b4", prev_log_index = 1, prev_log_term = 2,
            leader_commit = 0, entries = {},
        }))
        assert.is_false(mismatch.success)
        assert.are.equal(0, mismatch.match_index)
        assert.are.equal(0, follower:last_index())

        local retry = assert(follower:handle_append({
            term = 2, leader_id = "b4", prev_log_index = 0, prev_log_term = 0,
            leader_commit = 1,
            entries = { { term = 2, kind = "controller", data = {} } },
        }))
        assert.is_true(retry.success)
        assert.are.equal(1, retry.match_index)
    end)

    it("overwrites a conflicting suffix rather than appending past it", function()
        local follower = make_node("b2", { "b1", "b2" })
        follower:handle_append({
            term = 1, leader_id = "b1", prev_log_index = 0, prev_log_term = 0,
            leader_commit = 0,
            entries = {
                { term = 1, kind = "controller", data = {} },
                { term = 1, kind = "owner", data = { topic = "a", partition = 1, owner = "b1" } },
            },
        })
        assert.are.equal(2, follower:last_index())

        follower:handle_append({
            term = 2, leader_id = "b3", prev_log_index = 1, prev_log_term = 1,
            leader_commit = 0,
            entries = { { term = 2, kind = "owner",
                          data = { topic = "b", partition = 1, owner = "b3" } } },
        })
        assert.are.equal(2, follower:last_index())
        assert.are.equal("b", follower:entry_at(2).data.topic)
    end)

    it("applies entries only up to the leader commit index", function()
        local follower, applied = make_node("b2", { "b1", "b2" })
        follower:handle_append({
            term = 1, leader_id = "b1", prev_log_index = 0, prev_log_term = 0,
            leader_commit = 1,
            entries = {
                { term = 1, kind = "controller", data = {} },
                { term = 1, kind = "owner", data = { topic = "a", partition = 1, owner = "b1" } },
            },
        })
        assert.are.equal(1, #applied)

        follower:handle_append({
            term = 1, leader_id = "b1", prev_log_index = 2, prev_log_term = 1,
            leader_commit = 2, entries = {},
        })
        assert.are.equal(2, #applied)
    end)

    it("never commits an entry from an earlier term on vote count alone", function()
        local node = make_node("b1", { "b1", "b2", "b3" })
        node.state.current_term = 1
        node.state.entries[1] = { term = 1, index = 1, kind = "owner",
                                  data = { topic = "a", partition = 1, owner = "b1" } }
        local term, generation = node:begin_election()
        node:record_vote("b2", term, generation)
        assert.is_true(node:is_leader())

        node.commit_index = 0
        node.match_index["b2"] = 1
        node:advance_commit()
        assert.are.equal(0, node.commit_index)

        node.match_index["b2"] = 2
        node:advance_commit()
        assert.are.equal(2, node.commit_index)
        assert.are.equal(2, node:term_at(node:last_index()))
    end)
end)

describe("raft snapshots", function()

    it("compacts the log and restores the applied state from the snapshot", function()
        local node, _, owners = make_node("b1", { "b1" }, { max_log_entries = 2 })
        local term, generation = node:begin_election()
        node:record_vote("b1", term, generation)

        for i = 1, 4 do
            node:propose(Node.KIND_OWNER,
                { topic = "orders", partition = i, owner = "b2" })
        end
        assert.is_true(node.state.base_index > 0)
        assert.is_truthy(node.state.snapshot)
        assert.are.equal("b2", owners()["orders/4"])
    end)

    it("asks for a snapshot when the leader has compacted past the follower", function()
        local follower = make_node("b2", { "b1", "b2" })
        follower.state.base_index = 5
        follower.state.base_term  = 2

        local reply = assert(follower:handle_append({
            term = 3, leader_id = "b1", prev_log_index = 2, prev_log_term = 2,
            leader_commit = 0, entries = {},
        }))
        assert.is_false(reply.success)
        assert.is_true(reply.need_snapshot)
    end)

    it("installs a snapshot and rebuilds ownership from it", function()
        local follower, _, owners = make_node("b2", { "b1", "b2" })
        local reply = assert(follower:handle_snapshot({
            term = 4, leader_id = "b1", last_index = 9, last_term = 3,
            state = { owners = { { key = "orders/1", owner = "b1" } } },
        }))
        assert.is_true(reply.ok)
        assert.are.equal(9, follower:last_index())
        assert.are.equal(3, follower:last_term())
        assert.are.equal(9, follower.last_applied)
        assert.are.equal("b1", owners()["orders/1"])
    end)

    it("ignores a snapshot from a stale leader", function()
        local follower = make_node("b2", { "b1", "b2" })
        follower.state.current_term = 6
        local reply = assert(follower:handle_snapshot({
            term = 2, leader_id = "b1", last_index = 9, last_term = 1, state = {},
        }))
        assert.is_false(reply.ok)
        assert.are.equal(0, follower:last_index())
    end)
end)

describe("raft controller fence", function()

    it("accepts only the term the cluster currently agrees on", function()
        local node = make_node("b1", { "b1", "b2" })
        node.state.current_term = 7
        node.leader_id = "b2"
        local fence = Fence.new(node)

        local term, leader = fence:highest()
        assert.are.equal(7, term)
        assert.are.equal("b2", leader)

        assert.is_true(fence:observe(7, "b2"))
        assert.is_nil((fence:observe(6, "b2")))
        assert.is_nil((fence:observe(8, "b2")))
        assert.is_nil((fence:observe(7, "b3")))
    end)

    it("refuses to hand out a claim unless this broker is the controller", function()
        local node = make_node("b1", { "b1", "b2" })
        local fence = Fence.new(node)
        local epoch, err = fence:claim("b1")
        assert.is_nil(epoch)
        assert.is_truthy(err:find("controller"))

        local term, generation = node:begin_election()
        node:record_vote("b2", term, generation)
        assert.are.equal(node:term(), fence:claim("b1"))
    end)
end)
