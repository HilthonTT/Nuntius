local socket  = require("socket")
local json    = require("dkjson")
local httpk   = require("src.server.http_kit")
local Reactor = require("src.server.reactor")
local Store   = require("src.cluster.raft.store")
local Node    = require("src.cluster.raft.node")
local Service = require("src.cluster.raft.service")
local ClusterServer = require("src.cluster.cluster_server")

local MEMBERS = { "b1", "b2", "b3" }
local PORTS   = { b1 = 19401, b2 = 19402, b3 = 19403 }

local function memory_store()
    return {
        state = Store.empty_state(),
        save = function(self, state) self.state = state; return true end,
    }
end

local function make_member(id)
    local owners = {}
    local node = Node.new({
        id     = id,
        peers  = MEMBERS,
        store  = memory_store(),
        election_min = 0.3,
        election_max = 0.9,
        apply  = function(entry)
            if entry.kind == Node.KIND_OWNER then
                owners[entry.data.topic .. "/" .. entry.data.partition] = entry.data.owner
            end
            return true
        end,
        snapshot = function() return { owners = {} } end,
        restore  = function() return true end,
    })
    return { id = id, node = node, owners = owners }
end

local function serve(reactor, member)
    local node = member.node
    local _, err = reactor:listen("127.0.0.1", PORTS[member.id], function(sock)
        local deadline = socket.gettime() + 5
        local headers, leftover = httpk.read_headers(reactor, sock, deadline)
        if not headers then pcall(function() sock:close() end); return end

        local _, path = httpk.request_line(headers)
        local clen = tonumber(httpk.header(headers, "Content%-Length")) or 0
        local body = httpk.read_body(reactor, sock, leftover, clen, deadline, 1024 * 1024)
        local args = body and json.decode(body) or nil

        local reply
        if type(args) == "table" then
            if path == "/cluster/raft/vote" then
                reply = node:handle_vote(args)
            elseif path == "/cluster/raft/append" then
                reply = node:handle_append(args)
            elseif path == "/cluster/raft/snapshot" then
                reply = node:handle_snapshot(args)
            end
        end

        pcall(function()
            httpk.respond(reactor, sock, 200, "application/json",
                json.encode(reply or {}), 5)
            sock:close()
        end)
    end)
    assert.is_nil(err)
end

local function addresses_for(id)
    local out = {}
    for _, other in ipairs(MEMBERS) do
        if other ~= id then out[other] = "127.0.0.1:" .. PORTS[other] end
    end
    return out
end

local function leaders(members)
    local found = {}
    for _, m in ipairs(members) do
        if m.node:is_leader() then found[#found + 1] = m end
    end
    return found
end

describe("raft over the cluster listener", function()

    it("elects one controller and replicates an ownership change to every member",
    function()
        local reactor = Reactor.new()
        local members, services = {}, {}

        for _, id in ipairs(MEMBERS) do
            local member = make_member(id)
            members[#members + 1] = member
            serve(reactor, member)
            services[id] = Service.new({
                node        = member.node,
                reactor     = reactor,
                addresses   = addresses_for(id),
                heartbeat_s = 0.1,
                rpc_timeout = 1,
                commit_wait = 5,
            })
        end

        local running = true
        for _, id in ipairs(MEMBERS) do
            reactor:spawn(function()
                services[id]:run(function() return running end)
            end)
        end

        local outcome
        reactor:spawn(function()
            local deadline = socket.gettime() + 15
            while #leaders(members) ~= 1 and socket.gettime() < deadline do
                reactor:sleep(0.05)
            end

            local elected = leaders(members)[1]
            if not elected then
                outcome = { error = "no controller was elected" }
            else
                local index, err = services[elected.id]:commit(Node.KIND_OWNER,
                    { topic = "orders", partition = 1, owner = "b2" })
                outcome = { leader = elected.id, index = index, error = err }

                local until_applied = socket.gettime() + 10
                while socket.gettime() < until_applied do
                    local done = 0
                    for _, m in ipairs(members) do
                        if m.owners["orders/1"] == "b2" then done = done + 1 end
                    end
                    if done == #members then break end
                    reactor:sleep(0.05)
                end
            end

            running = false
            reactor:sleep(0.2)
            reactor:stop()
        end)

        reactor:spawn(function()
            reactor:sleep(30)
            running = false
            reactor:stop()
        end)

        reactor:run()
        reactor:shutdown()

        assert.is_truthy(outcome, "the driver never finished")
        assert.is_nil(outcome.error)
        assert.is_truthy(outcome.index)
        assert.are.equal(1, #leaders(members))

        for _, m in ipairs(members) do
            assert.are.equal("b2", m.owners["orders/1"],
                m.id .. " never applied the committed ownership change")
        end
    end)
end)

describe("cluster server raft routes", function()

    local function stub_server(node)
        return setmetatable({ raft = node }, { __index = ClusterServer })
    end

    it("dispatches each route to the matching handler", function()
        local node = Node.new({ id = "b1", peers = { "b1", "b2" }, store = memory_store() })
        local cs = stub_server(node)

        local status, out = cs:_raft("/cluster/raft/vote", json.encode({
            term = 3, candidate_id = "b2", last_log_index = 0, last_log_term = 0,
        }))
        assert.are.equal(200, status)
        assert.is_true(out.granted)

        status, out = cs:_raft("/cluster/raft/append", json.encode({
            term = 3, leader_id = "b2", prev_log_index = 0, prev_log_term = 0,
            leader_commit = 0, entries = {},
        }))
        assert.are.equal(200, status)
        assert.is_true(out.success)

        status, out = cs:_raft("/cluster/raft/snapshot", json.encode({
            term = 3, leader_id = "b2", last_index = 4, last_term = 3, state = {},
        }))
        assert.are.equal(200, status)
        assert.is_true(out.ok)
    end)

    it("answers 503 when consensus is not enabled and 400 on a bad body", function()
        local status = stub_server(nil):_raft("/cluster/raft/vote", "{}")
        assert.are.equal(503, status)

        local node = Node.new({ id = "b1", peers = { "b1" }, store = memory_store() })
        local cs = stub_server(node)
        assert.are.equal(400, (cs:_raft("/cluster/raft/vote", "not json")))
        assert.are.equal(400, (cs:_raft("/cluster/raft/vote", json.encode({ term = 1 }))))
    end)
end)
