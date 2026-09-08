local socket = require("socket")
local json   = require("dkjson")
local msg_m  = require("src.record.message")
local httpk  = require("src.server.http_kit")
local tls_m  = require("src.io.tls")
local util_m = require("src.core.util")
local ControllerFence = require("src.cluster.controller_fence")
local local_loads = require("src.cluster.local_loads")
local log    = require("src.log.logger").get("cluster_server")

local M = {}
M.__index = M

local READ_DEADLINE  = 10
local WRITE_DEADLINE = 5
local MAX_BODY       = 8 * 1024 * 1024
local MAX_PARTITIONS = 1024

function M.new(opts)
    local broker = assert(opts.broker, "broker required")
    local fence = opts.fence
    if not fence then
        local f, ferr = ControllerFence.new(broker.topic_manager.baseDir)
        if not f then error("controller fence: " .. tostring(ferr)) end
        fence = f
    end
    return setmetatable({
        reactor     = assert(opts.reactor, "reactor required"),
        broker      = broker,
        assignments = assert(opts.assignments, "assignments required"),
        broker_id   = assert(opts.broker_id, "broker_id required"),
        host        = opts.host or "127.0.0.1",
        port        = assert(opts.port, "port required"),
        token       = opts.token,
        fence       = fence,
        raft        = opts.raft,
        tls         = opts.tls,
        group_coordinator = opts.group_coordinator,
    }, M)
end

local function token_ok(expect, got)
    if not expect then return true end
    if type(got) ~= "string" then return false end
    local diff = #expect ~ #got
    for i = 1, math.max(#expect, #got) do
        diff = diff | ((expect:byte(i) or 0) ~ (got:byte(i) or 0))
    end
    return diff == 0
end


local function decode_body(body, label, spec)
    local req = json.decode(body or "")
    local names, ok = {}, type(req) == "table"
    for i = 1, #spec, 2 do
        names[#names + 1] = spec[i]
        if ok and type(req[spec[i]]) ~= spec[i + 1] then ok = false end
    end
    if not ok then
        return nil, string.format("%s: need {%s}", label, table.concat(names, ", "))
    end
    return req
end

function M:_ensure(body)
    local req, derr = decode_body(body, "ensure", { "topic", "string", "partitions", "number" })
    if not req then return 400, derr end
    local valid, verr = util_m.validate_topic_name(req.topic)
    if not valid then return 400, "ensure: " .. tostring(verr) end
    if req.partitions < 1 or req.partitions > MAX_PARTITIONS then
        return 400, "ensure: partitions out of range"
    end

    local existing = self.broker.topic_manager.topics[req.topic]
    if existing then
        if #existing.partitions < req.partitions then
            return 400, string.format(
                "ensure: topic exists with %d partitions, need %d",
                #existing.partitions, req.partitions)
        end
        return 200, { ok = true }
    end

    local _, cerr = self.broker:create_topic(req.topic, req.partitions)
    if cerr then return 500, "ensure: " .. tostring(cerr) end
    log:info("created topic %s (%d partitions) for reassignment",
        req.topic, req.partitions)
    return 200, { ok = true }
end

function M:_append(topic_name, partition_id, payload, forwarded)
    local topic, terr = self.broker:get_topic(topic_name)
    if not topic then return 404, "append: " .. tostring(terr) end
    local part = topic.partitions[partition_id]
    if not part then return 404, "append: no such partition" end

    local pos, applied, first_offset = 1, 0, nil
    while pos <= #payload do
        if #payload - pos + 1 < 8 then return 400, "append: short record header" end
        local total_size = string.unpack(">I8", payload, pos)
        if total_size < msg_m.MIN_BODY or total_size > #payload - pos - 7 then
            return 400, "append: truncated or corrupt record body"
        end
        local msg, derr = msg_m.decode_body(payload:sub(pos + 8, pos + 7 + total_size))
        if not msg then return 400, "append: decode: " .. tostring(derr) end

        local woff, werr = part:write_message(msg)
        if werr then return 500, "append: write: " .. tostring(werr) end
        if first_offset == nil then first_offset = woff end
        if forwarded and self.broker.traffic then
            self.broker.traffic:add_in(topic_name, partition_id, #msg.key + #msg.value)
        end
        applied = applied + 1
        pos = pos + 8 + total_size
    end

    -- Capture the post-append LEO *before* request_sync: with a group
    -- committer attached it yields, and other writers to this partition may
    -- append in the meantime. The forwarder derives the acked record offset
    -- from these values, so they must describe this batch only.
    local leo = part.offset
    if applied > 0 and part.request_sync then
        local sok, serr = part:request_sync()
        if not sok then return 500, "append: sync: " .. tostring(serr) end
    end
    return 200, { offset = leo, first_offset = first_offset, applied = applied }
end

function M:_leo(query)
    local q = httpk.parse_query(query)
    local partition_id = tonumber(q.partition)
    if type(q.topic) ~= "string" or not partition_id then
        return 400, "leo: need topic & partition"
    end
    local topic, terr = self.broker:get_topic(q.topic)
    if not topic then return 404, "leo: " .. tostring(terr) end
    local part = topic.partitions[partition_id]
    if not part then return 404, "leo: no such partition" end
    return 200, { offset = part.offset }
end

function M:_owner(body)
    local req, derr = decode_body(body, "owner", {
        "topic", "string", "partition", "number", "owner", "string",
    })
    if not req then return 400, derr end
    if req.partition < 1 or req.partition % 1 ~= 0 then
        return 400, "owner: partition must be a positive integer"
    end
    local ok, err = self.assignments:set_owner(req.topic, req.partition, req.owner)
    if not ok then return 500, "owner: " .. tostring(err) end
    log:info("ownership: %s/partition-%d -> %s", req.topic, req.partition, req.owner)
    return 200, { ok = true }
end

function M:_claim(body)
    local req, derr = decode_body(body, "claim", { "epoch", "number", "broker_id", "string" })
    if not req then return 400, derr end
    local ok, err = self.fence:observe(req.epoch, req.broker_id)
    local highest = self.fence:highest()
    if ok then
        log:info("controller claim accepted: epoch %d by %s", req.epoch, req.broker_id)
        return 200, { accepted = true, highest = highest }
    end
    log:warn("controller claim rejected: epoch %d by %s (%s)",
        req.epoch, req.broker_id, tostring(err))
    return 200, { accepted = false, highest = highest, reason = err }
end

function M:_check_fence(headers)
    local epoch = httpk.header(headers, "X%-Controller%-Epoch")
    if not epoch then return true end
    local id = httpk.header(headers, "X%-Controller%-Id")
    return self.fence:observe(tonumber(epoch), id)
end

function M:_offsets(body)
    local req, derr = decode_body(body, "offsets", {
        "topic", "string", "partition", "number", "offsets", "table",
    })
    if not req then return 400, derr end
    local applied, failed = 0, 0
    for group, offset in pairs(req.offsets) do
        if type(group) == "string" and type(offset) == "number" then
            local existing = self.broker:fetch_offset(group, req.topic, req.partition)
            if existing == nil or offset > existing then
                local ok, cerr = self.broker:commit_offset(
                    group, req.topic, req.partition, offset)
                if ok then
                    applied = applied + 1
                else
                    failed = failed + 1
                    log:error("offsets: commit %s %s/partition-%d=%d failed: %s",
                        group, req.topic, req.partition, offset, tostring(cerr))
                end
            end
        end
    end
    if failed > 0 then
        return 500, string.format("offsets: %d commit(s) failed", failed)
    end
    log:info("offsets: applied %d migrated offset(s) for %s/partition-%d",
        applied, req.topic, req.partition)
    return 200, { ok = true, applied = applied }
end

function M:_txn_enroll(body)
    local req, derr = decode_body(body, "txn/enroll", {
        "txn", "string", "topic", "string", "partition", "number", "first_offset", "number",
    })
    if not req then return 400, derr end
    local txns = self.broker.transactions
    if not txns then return 500, "txn/enroll: no transaction coordinator" end
    txns:remote_enroll(req.txn, req.topic, req.partition, req.first_offset)
    return 200, { ok = true }
end

function M:_txn_resolve(body)
    local req, derr = decode_body(body, "txn/resolve", {
        "txn", "string", "topic", "string", "partition", "number",
    })
    if not req then return 400, derr end
    local txns = self.broker.transactions
    if not txns then return 500, "txn/resolve: no transaction coordinator" end
    local ok, err = txns:remote_resolve(req.txn, req.topic, req.partition, {
        aborted = req.aborted == true,
        pid     = req.pid,
        epoch   = req.epoch,
        first   = req.first,
        upto    = req.upto,
    })
    if not ok then return 500, "txn/resolve: " .. tostring(err) end
    return 200, { ok = true }
end

function M:_group_join(body)
    local req, derr = decode_body(body, "group/join", {
        "group", "string", "member", "string", "topics", "table", "origin", "string",
    })
    if not req then return 400, derr end
    for _, t in ipairs(req.topics) do
        if type(t) ~= "string" then return 400, "group/join: topics must be strings" end
    end
    local gc = self.group_coordinator
    if not gc then return 500, "group/join: no group coordinator" end

    local group, gerr = gc:get_or_create(req.group)
    if not group then
        return 200, { ok = false, code = "limit", reason = gerr }
    end
    local assignment, jerr = group:join(req.member, req.topics, req.origin)
    if not assignment then
        local code = (jerr and jerr:find("get topic", 1, true)) and "topic" or "internal"
        return 200, { ok = false, code = code, reason = jerr }
    end
    log:info("group %s: forwarded join of %s (origin %s)",
        req.group, req.member, req.origin)
    return 200, { ok = true, assignment = assignment }
end

function M:_group_heartbeat(body)
    local req, derr = decode_body(body, "group/heartbeat", {
        "group", "string", "member", "string",
    })
    if not req then return 400, derr end
    local gc = self.group_coordinator
    if not gc then return 500, "group/heartbeat: no group coordinator" end

    local group = gc:get(req.group)
    if not group then return 200, { ok = false, reason = "unknown group" } end
    local ok, herr = group:heartbeat(req.member)
    if not ok then return 200, { ok = false, reason = herr or "unknown member" } end
    local member = group.members[req.member]
    return 200, { ok = true, assignment = (member and member.partitions) or {} }
end

function M:_group_leave(body)
    local req, derr = decode_body(body, "group/leave", { "group", "string", "member", "string" })
    if not req then return 400, derr end
    local gc = self.group_coordinator
    if not gc then return 500, "group/leave: no group coordinator" end

    local group = gc:get(req.group)
    if group then group:leave(req.member) end
    return 200, { ok = true }
end

function M:_raft(path, body)
    local node = self.raft
    if not node then return 503, "raft: controller consensus is not enabled" end

    local args = json.decode(body or "")
    if type(args) ~= "table" then return 400, "raft: body must be a JSON object" end

    local reply, err
    if path == "/cluster/raft/vote" then
        reply, err = node:handle_vote(args)
    elseif path == "/cluster/raft/append" then
        reply, err = node:handle_append(args)
    else
        reply, err = node:handle_snapshot(args)
    end
    if not reply then return 400, tostring(err) end
    return 200, reply
end

function M:_loads()
    return 200, { broker_id = self.broker_id,
                  loads = local_loads.collect(self.broker, self.assignments) }
end


function M:_handle(sock)
    local deadline = socket.gettime() + READ_DEADLINE
    local headers, leftover = httpk.read_headers(self.reactor, sock, deadline)
    if not headers then pcall(function() sock:close() end); return end

    local method, path, query = httpk.request_line(headers)
    local clen = tonumber(httpk.header(headers, "Content%-Length")) or 0

    local MUTATING = {
        ["/cluster/append"]      = true,
        ["/cluster/ensure"]      = true,
        ["/cluster/owner"]       = true,
        ["/cluster/offsets"]     = true,
        ["/cluster/txn/enroll"]  = true,
        ["/cluster/txn/resolve"] = true,
        ["/cluster/group/join"]      = true,
        ["/cluster/group/heartbeat"] = true,
        ["/cluster/group/leave"]     = true,
    }

    local status, out
    local authed = token_ok(self.token, httpk.header(headers, "X%-Cluster%-Token"))
    local fence_ok, fence_err = true, nil
    if authed and method == "POST" and MUTATING[path] then
        fence_ok, fence_err = self:_check_fence(headers)
    end
    if not authed then
        status, out = 401, "bad or missing X-Cluster-Token"
    elseif not fence_ok then
        status, out = 409, "fenced: " .. tostring(fence_err)
    elseif method == "POST" and path == "/cluster/append" then
        local topic     = httpk.header(headers, "X%-Topic")
        local partition = tonumber(httpk.header(headers, "X%-Partition"))
        if not topic or not partition then
            status, out = 400, "append: missing X-Topic/X-Partition"
        else
            local payload, berr = httpk.read_body(
                self.reactor, sock, leftover, clen, deadline, MAX_BODY)
            if not payload then
                status, out = 400, "append: body: " .. tostring(berr)
            else
                local forwarded =
                    httpk.header(headers, "X%-Forwarded%-Produce") ~= nil
                status, out = self:_append(topic, partition, payload, forwarded)
            end
        end
    elseif method == "POST" and (path == "/cluster/raft/vote"
        or path == "/cluster/raft/append" or path == "/cluster/raft/snapshot") then
        local body, berr = httpk.read_body(
            self.reactor, sock, leftover, clen, deadline, MAX_BODY)
        if not body then
            status, out = 400, "body: " .. tostring(berr)
        else
            status, out = self:_raft(path, body)
        end
    elseif method == "POST" and (path == "/cluster/ensure" or path == "/cluster/owner"
        or path == "/cluster/offsets" or path == "/cluster/controller/claim"
        or path == "/cluster/txn/enroll" or path == "/cluster/txn/resolve"
        or path == "/cluster/group/join" or path == "/cluster/group/heartbeat"
        or path == "/cluster/group/leave") then
        local body, berr = httpk.read_body(
            self.reactor, sock, leftover, clen, deadline, MAX_BODY)
        if not body then
            status, out = 400, "body: " .. tostring(berr)
        elseif path == "/cluster/ensure" then
            status, out = self:_ensure(body)
        elseif path == "/cluster/offsets" then
            status, out = self:_offsets(body)
        elseif path == "/cluster/controller/claim" then
            status, out = self:_claim(body)
        elseif path == "/cluster/txn/enroll" then
            status, out = self:_txn_enroll(body)
        elseif path == "/cluster/txn/resolve" then
            status, out = self:_txn_resolve(body)
        elseif path == "/cluster/group/join" then
            status, out = self:_group_join(body)
        elseif path == "/cluster/group/heartbeat" then
            status, out = self:_group_heartbeat(body)
        elseif path == "/cluster/group/leave" then
            status, out = self:_group_leave(body)
        else
            status, out = self:_owner(body)
        end
    elseif method == "GET" and path == "/cluster/leo" then
        status, out = self:_leo(query)
    elseif method == "GET" and path == "/cluster/loads" then
        status, out = self:_loads()
    else
        status, out = 404, "unknown cluster route"
    end

    local ctype, body
    if type(out) == "table" then
        ctype, body = "application/json", json.encode(out)
    else
        ctype, body = "text/plain", tostring(out) .. "\n"
        if status >= 500 then log:error("%s %s: %s", method, path, out) end
    end

    pcall(function()
        httpk.respond(self.reactor, sock, status, ctype, body, WRITE_DEADLINE)
        sock:close()
    end)
end

function M:start()
    local _, lerr = self.reactor:listen(self.host, self.port,
        function(sock) self:_handle(sock) end,
        { tls = self.tls })
    if lerr then
        log:error("cluster listen failed on %s:%d: %s", self.host, self.port, lerr)
        return nil, lerr
    end
    log:info("cluster endpoint listening on %s:%d (broker_id=%s%s, %s%s)",
        self.host, self.port, self.broker_id,
        self.token and ", token auth on" or "", tls_m.describe(self.tls),
        self.raft and ", raft consensus on" or "")
    return true
end

return M
