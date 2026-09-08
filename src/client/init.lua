local socket = require("socket")
local proto = require("src.wire.protocol")
local uuid = require("src.core.uuid")
local msg_m = require("src.record.message")
local dlq_env = require("src.record.dlq_envelope")
local scram = require("src.server.scram")
local pbkdf2 = require("src.core.pbkdf2")
local rng = require("src.core.rng")
local tls_m = require("src.io.tls")

local DEFAULT_TIMEOUT = 30

local CODEC_BY_NAME = {
    none   = msg_m.CODEC_NONE,
    gzip   = msg_m.CODEC_GZIP,
    snappy = msg_m.CODEC_SNAPPY,
}

local Client = {}
Client.__index = Client

function Client.new(opts)
    opts = opts or {}
    local host = opts.host or "127.0.0.1"
    local port = opts.port or 9092

    local cbind = nil
    local sock, cerr = socket.connect(host, port)
    if not sock then
        return nil, string.format("connect %s:%d: %s", host, port, tostring(cerr))
    end

    if opts.tls then
        local cfg, terr = tls_m.client_config(opts.tls, "client tls")
        if not cfg then
            sock:close()
            return nil, terr or "tls: nothing configured"
        end
        local ok, aerr = tls_m.require_available("client tls")
        if not ok then
            sock:close()
            return nil, aerr
        end
        sock:settimeout(opts.timeout or DEFAULT_TIMEOUT)
        local secured, herr = tls_m.connect_handshake(
            sock, cfg, host, opts.timeout or DEFAULT_TIMEOUT)
        if not secured then
            return nil, string.format("tls %s:%d: %s", host, port, tostring(herr))
        end
        sock = secured
        if opts.channel_binding ~= false then
            cbind = tls_m.peer_endpoint_hash(sock)
        end
    end

    local c = setmetatable({
        sock = sock,
        cbind = cbind,
        reactor = opts.reactor,
        timeout = opts.timeout or DEFAULT_TIMEOUT,
        host = host,
        port = port,
        closed = false,
        push_handler = nil,
        pid = nil,
        compression = CODEC_BY_NAME[tostring(opts.compression or "none"):lower()]
                      or msg_m.CODEC_NONE,
        isolation = (tostring(opts.isolation or "read_uncommitted"):lower()
                     == "read_committed")
                    and proto.ISOLATION_READ_COMMITTED
                    or proto.ISOLATION_READ_UNCOMMITTED,
        next_seq = {},
        group_id = nil,
        member_id = nil,
    }, Client)

    if not c.reactor then
        sock:settimeout(c.timeout)
    end

    local hcorrel = uuid.bytes()
    local ok, err = c:_write(proto.encode_hello(hcorrel))
    if not ok then c:close(); return nil, "send hello: " .. err end

    local op, _, payload, rerr = c:_read_until(hcorrel)
    if not op then c:close(); return nil, "read welcome: " .. rerr end
    if op == proto.OP_ERROR then
        local e = proto.decode_error(payload)
        c:close()
        return nil, "hello: " .. (e and e.message or "?")
    end
    if op ~= proto.OP_WELCOME then
        c:close()
        return nil, string.format("expected WELCOME, got 0x%02x", op)
    end

    if opts.client_name then
        local idc = uuid.bytes()
        c:_write(proto.encode_identify_client(idc,
            opts.client_name, opts.client_version or "0.0.0"))
        c:_read_until(idc)
    end

    if opts.username then
        local mechanism = tostring(opts.mechanism or "plain"):lower()
        if mechanism == "scram" or mechanism == "scram-sha-256" then
            local aerr = c:_auth_scram(opts.username, opts.password or "")
            if aerr then c:close(); return nil, aerr end
        else
            local acorrel = uuid.bytes()
            ok, err = c:_write(proto.encode_auth(acorrel,
                opts.username, opts.password or ""))
            if not ok then c:close(); return nil, "send auth: " .. err end

            op, _, payload, rerr = c:_read_until(acorrel)
            if not op then c:close(); return nil, "read auth_ok: " .. rerr end
            if op == proto.OP_ERROR then
                local e = proto.decode_error(payload)
                c:close()
                return nil, "auth: " .. (e and e.message or "?")
            end
            if op ~= proto.OP_AUTH_OK then
                c:close()
                return nil, string.format("expected AUTH_OK, got 0x%02x", op)
            end
        end
    end

    if opts.producer_name or opts.idempotent then
        local icorrel = uuid.bytes()
        ok, err = c:_write(proto.encode_init_producer_id(icorrel,
            opts.producer_name))
        if not ok then c:close(); return nil, "send init_producer_id: " .. err end

        op, _, payload, rerr = c:_read_until(icorrel)
        if not op then c:close(); return nil, "read producer_id: " .. rerr end
        if op == proto.OP_ERROR then
            local e = proto.decode_error(payload)
            c:close()
            return nil, "init_producer_id: " .. (e and e.message or "?")
        end
        if op ~= proto.OP_PRODUCER_ID then
            c:close()
            return nil, string.format("expected PRODUCER_ID, got 0x%02x", op)
        end
        local pinfo, perr = proto.decode_producer_id(payload)
        if not pinfo then
            c:close()
            return nil, "decode producer_id: " .. perr
        end
        c.pid   = pinfo.pid
        c.epoch = pinfo.epoch
        c.producer_name = opts.producer_name
    end

    return c
end

function Client:_mark_closed_on(err)
    if err == "closed" then self.closed = true end
end

function Client:_write(data)
    if self.closed then return nil, "closed" end

    if self.reactor then
        local ok, err = self.reactor:send_all(self.sock, data, nil)
        if not ok then self:_mark_closed_on(err) end
        return ok, err
    end
    local sent, err = self.sock:send(data)
    if err then
        self:_mark_closed_on(err)
        return nil, err
    end
    return sent == #data, nil
end

function Client:_read_bytes(n)
    if self.closed then return nil, "closed" end

    if self.reactor then
        local data, err = self.reactor:read_exact(self.sock, n, nil)
        if not data then self:_mark_closed_on(err) end
        return data, err
    end

    local buf = self.rx_partial or ""
    while #buf < n do
        local data, err, partial = self.sock:receive(n - #buf)
        if data then
            buf = buf .. data
        else
            if partial and #partial > 0 then buf = buf .. partial end
            if #buf < n then
                self.rx_partial = buf
                self:_mark_closed_on(err)
                return nil, err
            end
        end
    end
    self.rx_partial = nil
    return buf, nil
end

function Client:_read_frame()
    if not self.rx_frame_len then
        local len_bytes, err = self:_read_bytes(4)
        if not len_bytes then return nil, nil, nil, err end
        local frame_len = string.unpack(">I4", len_bytes)
        if frame_len > 16 * 1024 * 1024 then
            return nil, nil, nil, "frame too large from server"
        end
        self.rx_frame_len = frame_len
    end
    local body, berr = self:_read_bytes(self.rx_frame_len)
    if not body then return nil, nil, nil, berr end
    self.rx_frame_len = nil
    return proto.parse_frame(body)
end

function Client:_read_until(target_correl)
    while true do
        local op, c, payload, err = self:_read_frame()
        if not op then return nil, nil, nil, err end

        if op == proto.OP_HEARTBEAT_REQ then
            self:_write(proto.encode_heartbeat_resp(c))
        elseif op == proto.OP_HEARTBEAT_RESP then
        elseif c == target_correl then
            return op, c, payload, nil
        elseif c == uuid.ZERO and op == proto.OP_RECORD and self.push_handler then
            local rec = self:_decode_record(payload)
            if rec then self.push_handler(rec) end
        end
    end
end

function Client:_call(encode, expect_op, expect_name)
    local correl = uuid.bytes()
    local ok, err = self:_write(encode(correl))
    if not ok then return nil, err end

    local op, _, payload, rerr = self:_read_until(correl)
    if not op then return nil, rerr end
    if op == proto.OP_ERROR then
        return nil, (proto.decode_error(payload) or { message = "?" }).message
    end
    if expect_op and op ~= expect_op then
        return nil, string.format("expected %s, got 0x%02x", expect_name, op)
    end
    return payload or "", op
end

function Client:_auth_scram(username, password)
    local client_nonce = scram.nonce(rng.bytes)
    local client_first, client_first_bare, gs2 = scram.client_first(
        username, client_nonce, self.cbind and scram.CBIND_TYPE or nil)

    local correl = uuid.bytes()
    local ok, err = self:_write(
        proto.encode_auth_scram(correl, scram.MECHANISM, client_first))
    if not ok then return "send scram client-first: " .. tostring(err) end

    local op, _, payload, rerr = self:_read_until(correl)
    if not op then return "read scram challenge: " .. tostring(rerr) end
    if op == proto.OP_ERROR then
        local e = proto.decode_error(payload)
        return "scram: " .. (e and e.message or "?")
    end
    if op ~= proto.OP_AUTH_CHALLENGE then
        return string.format("expected AUTH_CHALLENGE, got 0x%02x", op)
    end

    local challenge, cerr = proto.decode_auth_challenge(payload)
    if not challenge then return "scram challenge: " .. tostring(cerr) end

    local server_first, serr = scram.parse_server_first(challenge.message, client_nonce)
    if not server_first then return "scram: " .. serr end

    local salted = pbkdf2.pbkdf2_hmac_sha256(password, server_first.salt,
        server_first.iterations, 32)
    local client_final, expected_signature = scram.client_final(
        salted, client_first_bare, challenge.message, server_first.nonce,
        gs2 .. (self.cbind or ""))

    local fcorrel = uuid.bytes()
    ok, err = self:_write(proto.encode_auth_scram_final(fcorrel, client_final))
    if not ok then return "send scram client-final: " .. tostring(err) end

    op, _, payload, rerr = self:_read_until(fcorrel)
    if not op then return "read auth_ok: " .. tostring(rerr) end
    if op == proto.OP_ERROR then
        local e = proto.decode_error(payload)
        return "scram: " .. (e and e.message or "?")
    end
    if op ~= proto.OP_AUTH_OK then
        return string.format("expected AUTH_OK, got 0x%02x", op)
    end

    local final, ferr = proto.decode_auth_ok(payload)
    if not final then return "scram server-final: " .. tostring(ferr) end
    local verified, verr = scram.verify_server_final(final.message, expected_signature)
    if not verified then return "scram: " .. verr end

    return nil
end

function Client:_decode_record(payload)
    local topic, p, err = proto.decode_string(payload, 1)
    if not topic then return nil, err end
    local partition, offset, timestamp = string.unpack(">I4I8I8", payload, p)
    p = p + 4 + 8 + 8
    local key, p2, kerr = proto.decode_string(payload, p)
    if not key then return nil, kerr end
    local value, _, verr = proto.decode_string(payload, p2)
    if not value then return nil, verr end
    return {
        topic     = topic,
        partition = partition,
        offset    = offset,
        timestamp = timestamp,
        key       = key,
        value     = value,
    }
end

function Client:produce(topic, key, value)
    assert(type(topic) == "string", "topic must be a string")
    assert(type(key) == "string", "key must be a string")

    local correl = uuid.bytes()
    local frame
    local seq_used

    if self.pid then
        seq_used = self.next_seq[topic] or 0
        frame = proto.encode_produce_idempotent(
            correl, self.pid, seq_used, topic, key, value,
            self.epoch or 0, self.compression)
    else
        frame = proto.encode_produce(correl, topic, key, value, self.compression)
    end

    local ok, err = self:_write(frame)
    if not ok then return nil, err end

    local op, _, payload, rerr = self:_read_until(correl)
    if not op then return nil, rerr end

    if op == proto.OP_ERROR or not payload then
        return nil, (proto.decode_error(payload) or { message = "?" }).message
    end
    local partition, offset = string.unpack(">I4I8", payload)
    if seq_used ~= nil then
        self.next_seq[topic] = seq_used + 1
    end
    return { partition = partition, offset = offset, seq = seq_used }
end

function Client:produce_batch(topic, records)
    assert(type(topic) == "string", "topic must be a string")
    assert(type(records) == "table" and #records > 0,
        "records must be a non-empty list")

    local normalized = {}
    for i = 1, #records do
        local r = records[i]
        if type(r) == "string" then
            normalized[i] = { key = "", value = r }
        else
            normalized[i] = { key = r.key or "", value = r.value or "" }
        end
    end

    local base_seq
    local opts = { codec = self.compression }
    if self.pid then
        base_seq       = self.next_seq[topic] or 0
        opts.pid       = self.pid
        opts.base_seq  = base_seq
        opts.epoch     = self.epoch or 0
    end

    local correl = uuid.bytes()
    local ok, err = self:_write(
        proto.encode_produce_batch(correl, topic, normalized, opts))
    if not ok then return nil, err end

    local op, _, payload, rerr = self:_read_until(correl)
    if not op then return nil, rerr end
    if op == proto.OP_ERROR or not payload then
        return nil, (proto.decode_error(payload) or { message = "?" }).message
    end
    if op ~= proto.OP_PRODUCE_BATCH_ACK then
        return nil, string.format("expected PRODUCE_BATCH_ACK, got 0x%02x", op)
    end

    local res, derr = proto.decode_produce_batch_ack(payload)
    if not res then return nil, "decode produce_batch_ack: " .. tostring(derr) end

    if base_seq ~= nil then
        for i = 1, #res.acks do res.acks[i].seq = base_seq + i - 1 end
        self.next_seq[topic] = base_seq + #res.acks
    end

    if res.code ~= 0 then
        return res.acks, res.message ~= "" and res.message
            or string.format("produce_batch failed after %d record(s)", #res.acks)
    end
    return res.acks, nil
end

function Client:produce_at_seq(topic, key, value, seq)
    assert(self.pid, "produce_at_seq requires an idempotent client")
    assert(type(seq) == "number" and seq >= 0, "seq must be a non-negative number")

    local correl = uuid.bytes()
    local frame = proto.encode_produce_idempotent(
        correl, self.pid, seq, topic, key, value, self.epoch or 0, self.compression)
    local ok, err = self:_write(frame)
    if not ok then return nil, err end

    local op, _, payload, rerr = self:_read_until(correl)
    if not op then return nil, rerr end
    if op == proto.OP_ERROR or not payload then
        return nil, (proto.decode_error(payload) or { message = "?" }).message
    end
    local partition, offset = string.unpack(">I4I8", payload)
    return { partition = partition, offset = offset, seq = seq }
end

function Client:fetch(topic, group, max_records, batched)
    max_records = max_records or 100
    if batched == nil then batched = true end

    local correl = uuid.bytes()
    local data = proto.encode_fetch(correl, topic, group, max_records,
        self.isolation, batched and proto.FETCH_FLAG_BATCHED or 0)
    local ok, err = self:_write(data)
    if not ok then return nil, err end

    local records = {}
    while true do
        local op, _, payload, rerr = self:_read_until(correl)
        if not op then return nil, rerr end
        if op == proto.OP_ERROR then
            return nil, (proto.decode_error(payload) or { message = "?" }).message
        end
        if op == proto.OP_OK then return records end
        if op == proto.OP_RECORD_BATCH then
            local batch, derr = proto.decode_record_batch(payload)
            if not batch then return nil, "decode record_batch: " .. tostring(derr) end
            for i = 1, #batch do records[#records + 1] = batch[i] end
        elseif op == proto.OP_RECORD then
            local r, derr = self:_decode_record(payload)
            if not r then return nil, "decode record: " .. tostring(derr) end
            records[#records + 1] = r
        else
            return nil, string.format("unexpected op 0x%02x during fetch", op)
        end
    end
end

function Client:subscribe(topic, group)
    local correl = uuid.bytes()
    local ok, err = self:_write(
        proto.encode_subscribe(correl, topic, group, self.isolation))
    if not ok then return nil, err end

    local op, _, payload, rerr = self:_read_until(correl)
    if not op then return nil, rerr end
    if op == proto.OP_ERROR then
        return nil, (proto.decode_error(payload) or { message = "?" }).message
    end
    if op ~= proto.OP_OK then
        return nil, string.format("expected OK for subscribe, got 0x%02x", op)
    end
    return true
end

function Client:next_record(timeout)
    local deadline = timeout and (socket.gettime() + timeout) or nil

    local original_timeout = self.timeout
    if not self.reactor then
        self.sock:settimeout(timeout and math.min(0.1, timeout) or 0.1)
    end

    local function restore()
        if not self.reactor then self.sock:settimeout(original_timeout) end
    end

    while true do
        if deadline and socket.gettime() > deadline then
            restore()
            return nil, "timeout"
        end

        local op, c, payload, err = self:_read_frame()
        if not op then
            if err == "timeout" then
            else
                restore()
                return nil, err
            end
        elseif op == proto.OP_HEARTBEAT_REQ then
            self:_write(proto.encode_heartbeat_resp(c))
        elseif op == proto.OP_RECORD and c == uuid.ZERO then
            restore()
            return self:_decode_record(payload)
        end
    end
end

function Client:commit(topic, partition, offset)
    local payload, err = self:_call(function(correl)
        return proto.encode_commit(correl, topic, partition, offset)
    end)
    if not payload then return nil, err end
    return true
end

function Client:nack(topic, partition, offset, reason)
    assert(type(topic) == "string", "topic must be a string")
    local payload, err = self:_call(function(correl)
        return proto.encode_nack(correl, topic, partition, offset, reason)
    end, proto.OP_NACK_ACK, "NACK_ACK")
    if not payload then return nil, err end
    return proto.decode_nack_ack(payload)
end

Client.decode_dlq_value = dlq_env.decode

function Client:create_topic(name, num_partitions)
    local payload, err = self:_call(function(correl)
        return proto.encode_create_topic(correl, name, num_partitions)
    end)
    if not payload then return nil, err end
    return true
end

function Client:list_topics()
    local payload, err = self:_call(proto.encode_list_topics)
    if not payload then return nil, err end
    return proto.decode_topic_list(payload)
end

function Client:list_offsets(topic)
    assert(type(topic) == "string", "topic must be a string")

    local payload, err = self:_call(function(correl)
        return proto.encode_list_offsets(correl, topic)
    end, proto.OP_OFFSETS, "OFFSETS")
    if not payload then return nil, err end
    return proto.decode_offsets(payload)
end

function Client:offsets_for_times(topic, timestamp_ms)
    assert(type(topic) == "string", "topic must be a string")
    assert(math.type(timestamp_ms) == "integer" and timestamp_ms >= 0,
        "timestamp_ms must be a non-negative integer (milliseconds)")

    local payload, err = self:_call(function(correl)
        return proto.encode_list_offsets(correl, topic, timestamp_ms)
    end, proto.OP_OFFSETS, "OFFSETS")
    if not payload then return nil, err end

    local entries, derr = proto.decode_offsets(payload)
    if not entries then return nil, derr end
    if not entries.for_times then
        return nil, "broker does not support offset-for-timestamp"
    end
    return entries.for_times
end

function Client:delete_topic(name)
    assert(type(name) == "string", "name must be a string")

    local payload, err = self:_call(function(correl)
        return proto.encode_delete_topic(correl, name)
    end)
    if not payload then return nil, err end
    return true
end

function Client:describe_topic(name)
    assert(type(name) == "string", "name must be a string")

    local payload, err = self:_call(function(correl)
        return proto.encode_describe_topic(correl, name)
    end, proto.OP_TOPIC_DESCRIPTION, "TOPIC_DESCRIPTION")
    if not payload then return nil, err end
    return proto.decode_topic_description(payload)
end

function Client:alter_topic_config(name, config)
    assert(type(name) == "string", "name must be a string")
    assert(type(config) == "table", "config must be a table")

    local payload, err = self:_call(function(correl)
        return proto.encode_alter_topic_config(correl, name, config)
    end)
    if not payload then return nil, err end
    return true
end

function Client:list_groups()
    local payload, err = self:_call(proto.encode_list_groups,
        proto.OP_GROUP_LIST, "GROUP_LIST")
    if not payload then return nil, err end
    return proto.decode_group_list(payload)
end

function Client:describe_group(group_id)
    assert(type(group_id) == "string", "group_id must be a string")

    local payload, err = self:_call(function(correl)
        return proto.encode_describe_group(correl, group_id)
    end, proto.OP_GROUP_DESCRIPTION, "GROUP_DESCRIPTION")
    if not payload then return nil, err end
    return proto.decode_group_description(payload)
end

function Client:delete_group(group_id)
    assert(type(group_id) == "string", "group_id must be a string")

    local payload, err = self:_call(function(correl)
        return proto.encode_delete_group(correl, group_id)
    end)
    if not payload then return nil, err end
    return true
end

function Client:join_group(group_id, topics, member_id)
    assert(type(group_id) == "string", "group_id must be a string")
    if type(topics) == "string" then topics = { topics } end
    assert(type(topics) == "table" and #topics > 0, "topics must be a non-empty list")

    local payload, err = self:_call(function(correl)
        return proto.encode_join_group(correl, group_id, member_id or "", topics)
    end, proto.OP_GROUP_ASSIGNMENT, "GROUP_ASSIGNMENT")
    if not payload then return nil, err end

    local res, derr = proto.decode_group_assignment(payload)
    if not res then return nil, "decode assignment: " .. tostring(derr) end
    self.group_id  = group_id
    self.member_id = res.member_id
    return res
end

function Client:group_heartbeat(group_id, member_id)
    group_id  = group_id  or self.group_id
    member_id = member_id or self.member_id
    assert(group_id and member_id, "not a member of any group (call join_group first)")

    local payload, err = self:_call(function(correl)
        return proto.encode_group_heartbeat(correl, group_id, member_id)
    end)
    if not payload then return nil, err end
    return true
end

function Client:leave_group(group_id, member_id)
    group_id  = group_id  or self.group_id
    member_id = member_id or self.member_id
    assert(group_id and member_id, "not a member of any group (call join_group first)")

    local payload, err = self:_call(function(correl)
        return proto.encode_leave_group(correl, group_id, member_id)
    end)
    if not payload then return nil, err end
    self.group_id  = nil
    self.member_id = nil
    return true
end


local function _txn_expect_ok(c, encode)
    local payload, err = c:_call(encode, proto.OP_OK, "OK")
    if not payload then return nil, err end
    return true
end

function Client:begin_transaction()
    assert(self.producer_name, "transactions require a producer_name client")
    return _txn_expect_ok(self, proto.encode_begin_txn)
end

function Client:commit_transaction()
    return _txn_expect_ok(self, function(correl)
        return proto.encode_end_txn(correl, true)
    end)
end

function Client:abort_transaction()
    return _txn_expect_ok(self, function(correl)
        return proto.encode_end_txn(correl, false)
    end)
end

function Client:send_offsets_to_transaction(group, offsets)
    assert(type(group) == "string", "group must be a string")
    assert(type(offsets) == "table", "offsets must be a list")
    return _txn_expect_ok(self, function(correl)
        return proto.encode_txn_offset_commit(correl, group, offsets)
    end)
end

function Client:close()
    if self.closed then return end
    self.closed = true
    pcall(function()
        self:_write(proto.encode_goodbye(uuid.bytes()))
        self.sock:close()
    end)
end


return Client
