local proto      = require("src.wire.protocol")
local Connection = require("src.server.connection")
local uuid       = require("src.core.uuid")
local consumer_m = require("src.broker.consumer")
local msg_m      = require("src.record.message")
local compression = require("src.record.compression")
local metrics    = require("src.metrics")
local acl_m      = require("src.server.acl")
local quota_m    = require("src.server.quota")
local scram_m    = require("src.server.scram")
local rng        = require("src.core.rng")
local log        = require("src.log.logger").get("server")
local push_log   = require("src.log.logger").get("push")

local M = {}


local function fail(conn, correl, code, fmt, ...)
    local message = select("#", ...) > 0 and string.format(fmt, ...) or fmt
    conn:send(proto.encode_error(correl, code, message))
    return false
end

local function write_err_code(err)
    return err:find("does not exist", 1, true)
        and proto.ERR_TOPIC_MISSING or proto.ERR_INTERNAL
end

local function decode(conn, correl, decoder, payload)
    local value, err = decoder(payload)
    if value then return value end
    fail(conn, correl, proto.ERR_BAD_FRAME, err)
    return nil
end

local function decode_or_close(conn, decoder, payload)
    local value, err = decoder(payload)
    if value then return value end
    conn:close(Connection.REASON_BAD_FRAME, proto.ERR_BAD_FRAME, err)
    return nil
end

local function permitted(conn, resource, name, operation)
    local principal = conn.principal
    if not principal then return true end
    return principal.acl:authorized(resource, name, operation)
end
M.permitted = permitted

local function authorize(conn, correl, resource, name, operation)
    if permitted(conn, resource, name, operation) then return true end

    metrics.inc("moonmq_authz_denied_total", 1,
        { resource = resource, operation = operation })
    log:warn("conn=%s user=%s DENIED %s on %s %q", conn.id_short,
        conn.username or "?", operation, resource, name or "*")
    fail(conn, correl, proto.ERR_NOT_AUTHORIZED,
        "not authorized: %s on %s %q", operation, resource, name or "*")
    return false
end
M.authorize = authorize

local function charge(server, conn, correl, topic, dim, amount)
    local quotas = server.quotas
    if not quotas then return true end

    local principal = conn.principal and conn.principal.username or nil
    local ok, retry, scope = quotas:check(principal, topic, dim, amount)
    if ok then return true end

    fail(conn, correl, proto.ERR_RATE_LIMITED,
        "%s quota exceeded on %s; retry in %.2fs", scope, dim, retry or 0)
    return false
end
M.charge = charge

local function charge_produce(server, conn, correl, topic, records, bytes)
    return charge(server, conn, correl, topic, quota_m.DIM_REQUESTS, 1)
       and charge(server, conn, correl, topic, quota_m.DIM_PRODUCE_RECORDS, records)
       and charge(server, conn, correl, topic, quota_m.DIM_PRODUCE_BYTES, bytes)
end

local function record_bytes(records)
    local total = 0
    for i = 1, #records do
        total = total + #records[i].key + #records[i].value
    end
    return total
end

local function meter_delivery(server, conn, records, count)
    if not server.quotas or count <= 0 then return 0 end

    local user = conn.principal and conn.principal.username or nil
    local counts, bytes, order = {}, {}, {}
    for i = 1, count do
        local r = records[i]
        if counts[r.topic] == nil then
            counts[r.topic], bytes[r.topic] = 0, 0
            order[#order + 1] = r.topic
        end
        counts[r.topic] = counts[r.topic] + 1
        bytes[r.topic]  = bytes[r.topic] + #r.key + #r.value
    end

    local wait = 0
    for _, topic in ipairs(order) do
        wait = math.max(wait, server.quotas:delay(user, topic,
            quota_m.DIM_FETCH_RECORDS, counts[topic]))
        wait = math.max(wait, server.quotas:delay(user, topic,
            quota_m.DIM_FETCH_BYTES, bytes[topic]))
    end
    return wait
end

local function delivery_allowed(server, conn, correl, topic)
    if not server.quotas then return true end

    local user = conn.principal and conn.principal.username or nil
    for _, dim in ipairs({ quota_m.DIM_FETCH_RECORDS, quota_m.DIM_FETCH_BYTES }) do
        local ok, retry, scope = server.quotas:available(user, topic, dim)
        if not ok then
            fail(conn, correl, proto.ERR_RATE_LIMITED,
                "%s quota exceeded on %s; retry in %.2fs", scope, dim, retry or 0)
            return false
        end
    end
    return true
end

local function build_stored_message(codec, key, value, txn)
    codec = codec or msg_m.CODEC_NONE
    local attrs = codec & msg_m.ATTR_CODEC_MASK
    local pid, epoch
    if txn then
        attrs = attrs | msg_m.ATTR_TXN
        pid, epoch = txn.pid, txn.epoch
    end
    if codec == msg_m.CODEC_NONE then
        return msg_m.Message.new(key, value, 0, attrs, pid, epoch)
    end
    if not compression.available(codec) then
        return nil, string.format("compression codec %s unavailable on this broker",
            compression.codec_name(codec))
    end
    local stored, cerr = compression.compress(codec, value)
    if not stored then
        return nil, string.format("compress (%s) failed: %s",
            compression.codec_name(codec), cerr)
    end
    return msg_m.Message.new(key, stored, 0, attrs, pid, epoch)
end

local function txn_err_code(code)
    if code == "fenced" then return proto.ERR_PRODUCER_FENCED end
    if code == "state"  then return proto.ERR_INVALID_TXN_STATE end
    return proto.ERR_INTERNAL
end

function M.hello(server, conn, correl, payload)
    local h = decode_or_close(conn, proto.decode_hello, payload)
    if not h then return end
    if h.version ~= proto.PROTOCOL_VERSION then
        conn:close(Connection.REASON_BAD_PROTOCOL, proto.ERR_BAD_PROTOCOL,
            string.format("expected v%d got v%d", proto.PROTOCOL_VERSION, h.version))
        return
    end
    conn:transition_to(Connection.STATE_GREETED)
    conn:send(proto.encode_welcome(correl, proto.PROTOCOL_VERSION))
end

function M.identify_client(server, conn, correl, payload)
    local i = decode(conn, correl, proto.decode_identify_client, payload)
    if not i then return end
    if #i.name > 128 or #i.version > 64 then
        return fail(conn, correl, proto.ERR_BAD_FRAME,
            "name (max 128) or version (max 64) too long")
    end
    conn.client_name    = i.name
    conn.client_version = i.version
    log:info("conn=%s identified client=%s/%s",
        conn.id_short, conn.client_name, conn.client_version)
    conn:send(proto.encode_identify_ack(correl,
        proto.SERVER_NAME, proto.SERVER_VERSION))
end

function M.auth(server, conn, correl, payload)
    local a = decode_or_close(conn, proto.decode_auth, payload)
    if not a then return end

    if not server.authenticator then
        log:warn("no authenticator configured, allowing")
        conn.username = a.username
        conn:transition_to(Connection.STATE_AUTHENTICATED)
        conn:send(proto.encode_auth_ok(correl))
        return
    end

    conn.auth_in_progress = true
    local called, ok, auth_err, principal =
        pcall(server.authenticator.verify, server.authenticator,
              a.username, a.password, conn.ip)
    conn.auth_in_progress = false
    if not called then
        log:error("conn=%s auth verify failed: %s", conn.id_short, tostring(ok))
        conn:close(Connection.REASON_AUTH_FAILED, proto.ERR_INTERNAL, "auth error")
        return
    end
    if not ok then
        metrics.inc("moonmq_auth_failures_total", 1, { mechanism = "plain" })
        conn:close(Connection.REASON_AUTH_FAILED, proto.ERR_AUTH_FAILED,
            auth_err or "auth failed")
        return
    end

    conn.username  = a.username
    conn.principal = principal
    metrics.inc("moonmq_auth_success_total", 1, { mechanism = "plain" })
    conn:transition_to(Connection.STATE_AUTHENTICATED)
    conn:send(proto.encode_auth_ok(correl))
end

function M.auth_scram(server, conn, correl, payload)
    local req = decode_or_close(conn, proto.decode_auth_scram, payload)
    if not req then return end

    if req.mechanism:upper() ~= scram_m.MECHANISM then
        conn:close(Connection.REASON_BAD_PROTOCOL, proto.ERR_BAD_PROTOCOL,
            string.format("unsupported mechanism %q (this broker speaks %s)",
                req.mechanism, scram_m.MECHANISM))
        return
    end

    if not server.authenticator then
        log:warn("no authenticator configured, refusing SCRAM")
        conn:close(Connection.REASON_AUTH_FAILED, proto.ERR_AUTH_FAILED,
            "broker has no credentials configured; connect without AUTH")
        return
    end

    local banned, remaining = server.authenticator:is_banned(conn.ip)
    if banned then
        conn:close(Connection.REASON_AUTH_FAILED, proto.ERR_AUTH_FAILED,
            string.format("ip banned for %d more seconds", remaining))
        return
    end

    local first, ferr = scram_m.parse_client_first(req.message)
    if not first then
        conn:close(Connection.REASON_BAD_PROTOCOL, proto.ERR_BAD_PROTOCOL, ferr)
        return
    end

    local tls_cfg = server.tls
    local bound, cberr = scram_m.negotiate_cbind(first,
        tls_cfg and tls_cfg.endpoint_hash or nil,
        tls_cfg and tls_cfg.channel_binding or "disabled")
    if not bound then
        conn:close(Connection.REASON_BAD_PROTOCOL, proto.ERR_BAD_PROTOCOL, cberr)
        return
    end

    local credential, principal = server.authenticator:scram_credential(first.username)
    local combined_nonce = first.nonce .. scram_m.nonce(rng.bytes)
    local server_first = scram_m.server_first(combined_nonce,
        credential.salt, credential.iterations)

    conn.scram = {
        username     = first.username,
        principal    = principal,
        credential   = credential,
        nonce        = combined_nonce,
        client_first = first.bare,
        gs2          = first.gs2,
        cbind        = bound,
        server_first = server_first,
    }

    conn:send(proto.encode_auth_challenge(correl, server_first))
end

function M.auth_scram_final(server, conn, correl, payload)
    local state = conn.scram
    if not state then
        conn:close(Connection.REASON_BAD_PROTOCOL, proto.ERR_BAD_PROTOCOL,
            "AUTH_SCRAM_FINAL without a preceding AUTH_SCRAM")
        return
    end
    conn.scram = nil

    local req = decode_or_close(conn, proto.decode_auth_scram_final, payload)
    if not req then return end

    local final, ferr = scram_m.parse_client_final(req.message)
    if not final then
        conn:close(Connection.REASON_BAD_PROTOCOL, proto.ERR_BAD_PROTOCOL, ferr)
        return
    end

    local function reject(reason)
        server.authenticator:note_failure(conn.ip)
        metrics.inc("moonmq_auth_failures_total", 1, { mechanism = "scram" })
        conn:close(Connection.REASON_AUTH_FAILED, proto.ERR_AUTH_FAILED, reason)
    end

    -- The ban check at AUTH_SCRAM time is not enough: the IP may have been
    -- banned by other connections between the two round trips.
    local banned = server.authenticator:is_banned(conn.ip)
    if banned then
        metrics.inc("moonmq_auth_failures_total", 1, { mechanism = "scram" })
        conn:close(Connection.REASON_AUTH_FAILED, proto.ERR_AUTH_FAILED,
            "too many failed attempts; try again later")
        return
    end

    if final.nonce ~= state.nonce then
        reject("scram nonce mismatch")
        return
    end
    if not scram_m.check_cbind(state.gs2, final.cbind, state.cbind) then
        reject("scram channel-binding mismatch")
        return
    end

    local auth_message = scram_m.auth_message(
        state.client_first, state.server_first, final.without_proof)

    if not scram_m.verify_proof(state.credential.stored_key, auth_message, final.proof)
       or not state.principal then
        reject("invalid credentials")
        return
    end

    server.authenticator:note_success(conn.ip)
    conn.username  = state.username
    conn.principal = state.principal
    metrics.inc("moonmq_auth_success_total", 1, { mechanism = "scram" })
    conn:transition_to(Connection.STATE_AUTHENTICATED)
    conn:send(proto.encode_auth_ok(correl,
        scram_m.server_final(state.credential.server_key, auth_message)))
end

function M.produce(server, conn, correl, payload)
    if conn.rate_limiter and not conn.rate_limiter:take(1) then
        return fail(conn, correl, proto.ERR_RATE_LIMITED, "produce rate exceeded")
    end

    local p = decode(conn, correl, proto.decode_produce, payload)
    if not p then return end

    if not authorize(conn, correl, acl_m.RES_TOPIC, p.topic, acl_m.OP_WRITE) then return end
    if not charge_produce(server, conn, correl, p.topic, 1, #p.key + #p.value) then return end

    local msg, berr = build_stored_message(p.codec, p.key, p.value)
    if not msg then
        return fail(conn, correl, proto.ERR_INTERNAL, berr)
    end
    local part_id, offset, werr = server.producer:produce(p.topic, msg)
    if werr then
        return fail(conn, correl, write_err_code(werr), werr)
    end

    metrics.inc("moonmq_produce_records_total", 1, { topic = p.topic })

    conn:send(proto.encode_produce_ack(correl, part_id, offset))
end

local function build_batch_messages(records, codec, txn)
    local msgs = {}
    for i = 1, #records do
        local r = records[i]
        local msg, berr = build_stored_message(codec, r.key, r.value, txn)
        if not msg then return nil, berr end
        msgs[i] = msg
    end
    return msgs, nil
end

local function seq_state_for(conn, ps, topic, durable)
    if durable then
        local m = ps:lookup_memo(conn.pid, topic)
        if m and (m.epoch or 0) == conn.epoch then return m end
        return { last_seq = -1 }
    end
    return conn.seq_state[topic] or { last_seq = -1 }
end

function M.produce_batch(server, conn, correl, payload)
    local b = decode(conn, correl, proto.decode_produce_batch, payload)
    if not b then return end
    local count = #b.records

    if conn.rate_limiter and not conn.rate_limiter:take(count) then
        return fail(conn, correl, proto.ERR_RATE_LIMITED, "produce rate exceeded")
    end

    if not authorize(conn, correl, acl_m.RES_TOPIC, b.topic, acl_m.OP_WRITE) then return end
    if not charge_produce(server, conn, correl, b.topic, count,
                          record_bytes(b.records)) then return end

    if not b.idempotent then
        local msgs, berr = build_batch_messages(b.records, b.codec)
        if not msgs then
            return fail(conn, correl, proto.ERR_INTERNAL, berr)
        end
        local acks, perr = server.producer:produce_batch(b.topic, msgs)
        if perr and #acks == 0 then
            return fail(conn, correl, write_err_code(perr), perr)
        end
        if #acks > 0 then
            metrics.inc("moonmq_produce_records_total", #acks, { topic = b.topic })
            metrics.inc("moonmq_produce_batches_total", 1, { topic = b.topic })
        end
        conn:send(proto.encode_produce_batch_ack(correl, acks,
            perr and proto.ERR_INTERNAL or 0, perr))
        return
    end

    if not conn.pid then
        return fail(conn, correl, proto.ERR_NO_PRODUCER_ID,
            "INIT_PRODUCER_ID required before an idempotent PRODUCE_BATCH")
    end
    if b.pid ~= conn.pid then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL,
            "pid mismatch: frame=%d conn=%d", b.pid, conn.pid)
    end
    if count > proto.MAX_IDEMPOTENT_BATCH then
        return fail(conn, correl, proto.ERR_BATCH_TOO_LARGE,
            "idempotent batch of %d exceeds the %d-record limit; split it", count,
            proto.MAX_IDEMPOTENT_BATCH)
    end

    local ps      = server.broker.producer_state
    local durable = conn.producer_name ~= nil

    if durable then
        local cur = ps:current_epoch(conn.pid)
        if cur ~= nil and b.epoch ~= cur then
            return fail(conn, correl, proto.ERR_PRODUCER_FENCED,
                "producer fenced: frame epoch %d != current %d", b.epoch, cur)
        end
    end

    local state    = seq_state_for(conn, ps, b.topic, durable)
    local last_seq = state.last_seq
    local base     = b.base_seq
    local last     = base + count - 1

    if state.acks and state.base_seq == base and last_seq == last then
        conn:send(proto.encode_produce_batch_ack(correl, state.acks, 0, nil))
        return
    end
    if base ~= last_seq + 1 then
        return fail(conn, correl, proto.ERR_OUT_OF_ORDER_SEQUENCE,
            "expected base seq %d, got %d..%d (pid=%d %s)", last_seq + 1, base, last, conn.pid,
            b.topic)
    end

    local in_txn = conn.in_txn and conn.producer_name ~= nil
    local msgs, berr = build_batch_messages(b.records, b.codec,
        in_txn and { pid = conn.pid, epoch = conn.epoch } or nil)
    if not msgs then
        return fail(conn, correl, proto.ERR_INTERNAL, berr)
    end

    local produce_opts
    local enrol_err, enrol_code
    if in_txn then
        produce_opts = {
            pre_append = function(topic_name, partition_id, _partition, remote)
                local pok, perr, pcode = server.broker.transactions:add_partition(
                    conn.producer_name, conn.pid, conn.epoch, topic_name, partition_id,
                    remote)
                if not pok then
                    enrol_err, enrol_code = perr, pcode
                    return nil, "failed to enrol partition in txn: " .. tostring(perr)
                end
                return true
            end,
        }
    end

    local acks, perr = server.producer:produce_batch(b.topic, msgs, produce_opts)

    if perr and #acks == 0 then
        if enrol_err then
            return fail(conn, correl, txn_err_code(enrol_code), perr)
        end
        return fail(conn, correl, write_err_code(perr), perr)
    end

    local applied  = #acks
    local last_ack = acks[applied]
    local memo     = { base_seq = base, acks = acks }
    if durable then
        local ok, rerr = ps:record_produce(conn.pid, b.topic, base + applied - 1,
            last_ack.offset, last_ack.partition, conn.epoch, memo)
        if not ok then
            conn:send(proto.encode_produce_batch_ack(correl, acks, proto.ERR_INTERNAL,
                "produced but failed to persist producer state: " .. tostring(rerr)))
            return
        end
    else
        conn.seq_state[b.topic] = {
            last_seq       = base + applied - 1,
            last_offset    = last_ack.offset,
            last_partition = last_ack.partition,
            base_seq       = base,
            acks           = acks,
        }
    end

    metrics.inc("moonmq_produce_records_total", applied, { topic = b.topic })
    metrics.inc("moonmq_idempotent_produce_total", applied, { topic = b.topic })
    metrics.inc("moonmq_produce_batches_total", 1, { topic = b.topic })

    conn:send(proto.encode_produce_batch_ack(correl, acks,
        perr and proto.ERR_INTERNAL or 0, perr))
end

function M.init_producer_id(server, conn, correl, payload)
    local req = decode(conn, correl, proto.decode_init_producer_id, payload)
    if not req then return end

    local ps = server.broker.producer_state

    if req.producer_name == "" then
        local pid = ps:allocate_ephemeral()
        conn.pid           = pid
        conn.epoch         = 0
        conn.producer_name = nil
        conn.seq_state     = {}
        log:info("conn=%s assigned ephemeral producer_id=%d", conn.id_short, pid)
        conn:send(proto.encode_producer_id(correl, pid, 0))
        return
    end

    local pid, epoch, gerr = ps:get_or_create_producer(req.producer_name)
    if not pid then
        return fail(conn, correl, proto.ERR_INTERNAL, gerr or "producer id allocation failed")
    end
    conn.pid           = pid
    conn.epoch         = epoch
    conn.producer_name = req.producer_name
    conn.seq_state     = {}
    log:info("conn=%s producer_id=%d epoch=%d name=%s",
        conn.id_short, pid, epoch, req.producer_name)
    conn:send(proto.encode_producer_id(correl, pid, epoch))
end

function M.produce_idempotent(server, conn, correl, payload)
    if conn.rate_limiter and not conn.rate_limiter:take(1) then
        return fail(conn, correl, proto.ERR_RATE_LIMITED, "produce rate exceeded")
    end

    if not conn.pid then
        return fail(conn, correl, proto.ERR_NO_PRODUCER_ID,
            "INIT_PRODUCER_ID required before PRODUCE_IDEMPOTENT")
    end

    local p = decode(conn, correl, proto.decode_produce_idempotent, payload)
    if not p then return end

    if p.pid ~= conn.pid then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL,
            "pid mismatch: frame=%d conn=%d", p.pid, conn.pid)
    end

    if not authorize(conn, correl, acl_m.RES_TOPIC, p.topic, acl_m.OP_WRITE) then return end
    if not charge(server, conn, correl, p.topic, quota_m.DIM_REQUESTS, 1) then return end

    local ps       = server.broker.producer_state
    local durable  = conn.producer_name ~= nil

    if durable then
        local cur = ps:current_epoch(conn.pid)
        if cur ~= nil and p.epoch ~= cur then
            return fail(conn, correl, proto.ERR_PRODUCER_FENCED,
                "producer fenced: frame epoch %d != current %d", p.epoch, cur)
        end
    end

    local state = seq_state_for(conn, ps, p.topic, durable)
    local last_seq, last_offset, last_partition =
        state.last_seq, state.last_offset, state.last_partition

    if p.seq == last_seq and last_offset ~= nil then
        conn:send(proto.encode_produce_ack(correl, last_partition, last_offset))
        return
    elseif p.seq < last_seq or p.seq > last_seq + 1 then
        return fail(conn, correl, proto.ERR_OUT_OF_ORDER_SEQUENCE,
            "expected seq %d, got %d (pid=%d %s)", last_seq + 1, p.seq, conn.pid, p.topic)
    end

    if not charge(server, conn, correl, p.topic,
                  quota_m.DIM_PRODUCE_RECORDS, 1) then return end
    if not charge(server, conn, correl, p.topic,
                  quota_m.DIM_PRODUCE_BYTES, #p.key + #p.value) then return end

    local in_txn = conn.in_txn and conn.producer_name ~= nil
    local msg, berr = build_stored_message(p.codec, p.key, p.value,
        in_txn and { pid = conn.pid, epoch = conn.epoch } or nil)
    if not msg then
        return fail(conn, correl, proto.ERR_INTERNAL, berr)
    end
    local produce_opts
    local enrol_err, enrol_code
    if in_txn then
        produce_opts = {
            pre_append = function(topic_name, partition_id, _partition, remote)
                local pok, perr, pcode = server.broker.transactions:add_partition(
                    conn.producer_name, conn.pid, conn.epoch, topic_name, partition_id,
                    remote)
                if not pok then
                    enrol_err, enrol_code = perr, pcode
                    return nil, "failed to enrol partition in txn: " .. tostring(perr)
                end
                return true
            end,
        }
    end
    local partition_id, offset, werr =
        server.producer:produce(p.topic, msg, produce_opts)
    if werr then
        if enrol_err then
            return fail(conn, correl, txn_err_code(enrol_code), werr)
        end
        return fail(conn, correl, write_err_code(werr), werr)
    end

    if durable then
        local ok, rerr = ps:record_produce(conn.pid, p.topic, p.seq,
            offset, partition_id, conn.epoch)
        if not ok then
            return fail(conn, correl, proto.ERR_INTERNAL,
                "produced but failed to persist producer state: " .. tostring(rerr))
        end
    else
        conn.seq_state[p.topic] = {
            last_seq       = p.seq,
            last_offset    = offset,
            last_partition = partition_id,
        }
    end

    metrics.inc("moonmq_produce_records_total", 1, { topic = p.topic })
    metrics.inc("moonmq_idempotent_produce_total", 1, { topic = p.topic })

    conn:send(proto.encode_produce_ack(correl, partition_id, offset))
end

local function ensure_consumer(conn, broker, group_id, isolation)
    local iso = (isolation == proto.ISOLATION_READ_COMMITTED)
        and "read_committed" or "read_uncommitted"
    if conn.consumer then
        if conn.consumer.group_id ~= group_id then
            return nil, string.format("group_id mismatch (already in group %s)",
                conn.consumer.group_id)
        end
        if conn.consumer.isolation ~= iso then
            return nil, string.format("isolation mismatch (connection is %s)",
                conn.consumer.isolation)
        end
        return conn.consumer
    end
    conn.consumer = consumer_m.Consumer.new(broker, group_id, { isolation = iso })
    return conn.consumer
end

local function subscriber_loop(server, conn)
    while conn.state ~= Connection.STATE_CLOSED do
        server.coordinator:apply_assignment(conn)
        local records, err = conn.consumer:poll({ max_records = server.push_batch })
        if err then
            push_log:error("conn=%s poll: %s", conn.id_short, err)
            return
        end
        if records and #records > 0 then
            local wait = meter_delivery(server, conn, records, #records)
            if wait > 0 then
                server.reactor:sleep(wait)
                if conn.state == Connection.STATE_CLOSED then return end
            end

            for i = 1, #records do
                if conn.state == Connection.STATE_CLOSED then return end
                local r = records[i]
                local frame = proto.encode_record(uuid.ZERO,
                    r.topic, r.partition, r.offset, r.timestamp, r.key, r.value)
                if not conn:send(frame) then return end
                metrics.inc("moonmq_fetch_records_total", 1, { topic = r.topic })
                server.broker.traffic:add_out(r.topic, r.partition, #r.key + #r.value)
                local adv = conn.consumer.offsets[r.topic]
                    and conn.consumer.offsets[r.topic][r.partition]
                if adv then
                    local cok, cerr =
                        conn.consumer:commit_offset(r.topic, r.partition, adv)
                    if not cok then
                        push_log:error("conn=%s commit: %s", conn.id_short, cerr)
                        return
                    end
                end
            end
        else
            server.reactor:sleep(server.push_interval)
        end
    end
end

function M.subscribe(server, conn, correl, payload)
    local s = decode(conn, correl, proto.decode_subscribe, payload)
    if not s then return end
    if conn.mode == "pull" then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL,
            "connection already in pull mode (used FETCH)")
    end

    if not authorize(conn, correl, acl_m.RES_TOPIC, s.topic, acl_m.OP_READ) then return end
    if not authorize(conn, correl, acl_m.RES_GROUP, s.group_id, acl_m.OP_READ) then return end
    if not charge(server, conn, correl, s.topic, quota_m.DIM_REQUESTS, 1) then return end

    local consumer, cerr = ensure_consumer(conn, server.broker, s.group_id, s.isolation)
    if not consumer then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL, cerr)
    end
    local sok, serr = consumer:subscribe(s.topic)
    if not sok then
        return fail(conn, correl, proto.ERR_TOPIC_MISSING, serr or "subscribe failed")
    end
    conn.subscriptions[s.topic] = true
    conn.mode = "push"
    consumer.auto_commit = false
    conn:send(proto.encode_ok(correl))

    if not conn.subscriber_co then
        conn.subscriber_co = server.reactor:spawn(function()
            subscriber_loop(server, conn)
        end)
    end
end

function M.fetch(server, conn, correl, payload)
    local f = decode(conn, correl, proto.decode_fetch, payload)
    if not f then return end
    if conn.mode == "push" then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL,
            "connection already in push mode (used SUBSCRIBE)")
    end

    if not authorize(conn, correl, acl_m.RES_TOPIC, f.topic, acl_m.OP_READ) then return end
    if not authorize(conn, correl, acl_m.RES_GROUP, f.group_id, acl_m.OP_READ) then return end
    if not charge(server, conn, correl, f.topic, quota_m.DIM_REQUESTS, 1) then return end
    if not delivery_allowed(server, conn, correl, f.topic) then return end

    local consumer, cerr = ensure_consumer(conn, server.broker, f.group_id, f.isolation)
    if not consumer then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL, cerr)
    end
    if not conn.subscriptions[f.topic] then
        local sok, sberr = consumer:subscribe(f.topic)
        if not sok then
            return fail(conn, correl, proto.ERR_TOPIC_MISSING, sberr or "subscribe failed")
        end
        conn.subscriptions[f.topic] = true
    end
    conn.mode = "pull"
    consumer.auto_commit = false

    server.coordinator:apply_assignment(conn)

    local records, perr = consumer:poll({ max_records = f.max_records })
    if perr then
        return fail(conn, correl, proto.ERR_INTERNAL, perr)
    end
    if records then
        local limit = math.min(#records, f.max_records or #records)

        for i = #records, limit + 1, -1 do
            local r = records[i]
            consumer.offsets[r.topic][r.partition] = r.offset
        end

        local delivered = limit
        if f.batched then
            local batch = {}
            for i = 1, limit do batch[i] = records[i] end
            if limit > 0 and not conn:send(proto.encode_record_batch(correl, batch)) then
                for i = limit, 1, -1 do
                    local r = records[i]
                    consumer.offsets[r.topic][r.partition] = r.offset
                end
                return
            end
            for i = 1, limit do
                local r = records[i]
                server.broker.traffic:add_out(r.topic, r.partition, #r.key + #r.value)
            end
        else
            for i = 1, limit do
                local r = records[i]
                local frame = proto.encode_record(correl,
                    r.topic, r.partition, r.offset, r.timestamp, r.key, r.value)
                if not conn:send(frame) then
                    for j = limit, i, -1 do
                        local rr = records[j]
                        consumer.offsets[rr.topic][rr.partition] = rr.offset
                    end
                    delivered = i - 1
                    break
                end
                server.broker.traffic:add_out(r.topic, r.partition, #r.key + #r.value)
            end
        end

        local advanced, order = {}, {}
        for i = 1, delivered do
            local r = records[i]
            local by_topic = advanced[r.topic]
            if not by_topic then
                by_topic = {}
                advanced[r.topic] = by_topic
            end
            if by_topic[r.partition] == nil then
                order[#order + 1] = { topic = r.topic, partition = r.partition }
            end
            by_topic[r.partition] = consumer.offsets[r.topic][r.partition]
        end
        for _, k in ipairs(order) do
            local cok, commit_err = consumer:commit_offset(
                k.topic, k.partition, advanced[k.topic][k.partition])
            if not cok then
                log:error("conn=%s fetch commit %s/partition-%d: %s",
                    conn.id_short, k.topic, k.partition, commit_err)
            end
        end

        if delivered > 0 then
            metrics.inc("moonmq_fetch_records_total", delivered, { topic = f.topic })
            meter_delivery(server, conn, records, delivered)
        end
    end
    conn:send(proto.encode_ok(correl))
end

function M.commit(server, conn, correl, payload)
    local c = decode(conn, correl, proto.decode_commit, payload)
    if not c then return end
    if not conn.consumer then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL,
            "commit requires prior subscribe/fetch")
    end
    if not authorize(conn, correl, acl_m.RES_TOPIC, c.topic, acl_m.OP_READ) then return end
    if not authorize(conn, correl, acl_m.RES_GROUP, conn.consumer.group_id,
                     acl_m.OP_READ) then return end
    if not charge(server, conn, correl, c.topic, quota_m.DIM_REQUESTS, 1) then return end
    local topic, terr = server.broker:get_topic(c.topic)
    if not topic then
        return fail(conn, correl, proto.ERR_TOPIC_MISSING, terr or "topic missing")
    end
    if c.partition < 1 or c.partition > #topic.partitions then
        return fail(conn, correl, proto.ERR_BAD_FRAME,
            "partition %d out of range (1..%d)", c.partition, #topic.partitions)
    end
    if not server.broker:serves_partition(c.topic, c.partition) then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL,
            "%s/partition-%d has moved to another broker; commit there", c.topic, c.partition)
    end
    if conn.group_id then
        if not server.coordinator:member_alive(conn.group_id, conn.member_id) then
            return fail(conn, correl, proto.ERR_GROUP_MEMBER_UNKNOWN,
                "group membership lapsed; rejoin before committing")
        end
    end
    local ok, cerr = conn.consumer:commit_offset(c.topic, c.partition, c.offset)
    if not ok then
        return fail(conn, correl, proto.ERR_INTERNAL, cerr or "commit failed")
    end
    conn:send(proto.encode_ok(correl))
end

function M.nack(server, conn, correl, payload)
    local n = decode(conn, correl, proto.decode_nack, payload)
    if not n then return end
    if not conn.consumer then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL, "nack requires prior subscribe/fetch")
    end
    if not authorize(conn, correl, acl_m.RES_TOPIC, n.topic, acl_m.OP_READ) then return end
    if not authorize(conn, correl, acl_m.RES_GROUP, conn.consumer.group_id,
                     acl_m.OP_READ) then return end
    if not charge(server, conn, correl, n.topic, quota_m.DIM_REQUESTS, 1) then return end
    local topic, terr = server.broker:get_topic(n.topic)
    if not topic then
        return fail(conn, correl, proto.ERR_TOPIC_MISSING, terr or "topic missing")
    end
    if n.partition < 1 or n.partition > #topic.partitions then
        return fail(conn, correl, proto.ERR_BAD_FRAME,
            "partition %d out of range (1..%d)", n.partition, #topic.partitions)
    end
    if not server.broker:serves_partition(n.topic, n.partition) then
        return fail(conn, correl, proto.ERR_BAD_PROTOCOL,
            "%s/partition-%d has moved to another broker; nack there", n.topic, n.partition)
    end
    if conn.group_id then
        if not server.coordinator:member_alive(conn.group_id, conn.member_id) then
            return fail(conn, correl, proto.ERR_GROUP_MEMBER_UNKNOWN,
                "group membership lapsed; rejoin before nacking")
        end
    end

    local group = conn.consumer.group_id
    local res, nerr = server.broker.dlq:record_failure(
        group, n.topic, n.partition, n.offset, n.reason)
    if not res then
        return fail(conn, correl, proto.ERR_INTERNAL, nerr)
    end
    metrics.inc("moonmq_nack_total", 1, { topic = n.topic })

    local offsets = conn.consumer.offsets[n.topic]
    local cur = offsets and offsets[n.partition]

    if res.dead_lettered then
        if offsets and (cur == nil or cur < res.next_offset) then
            offsets[n.partition] = res.next_offset
        end
        local cok, cerr = conn.consumer:commit_offset(
            n.topic, n.partition, res.next_offset)
        if not cok then
            log:error("conn=%s nack advance %s/partition-%d: %s",
                conn.id_short, n.topic, n.partition, cerr)
        end
        metrics.inc("moonmq_dlq_records_total", 1, { topic = n.topic })
        conn:send(proto.encode_nack_ack(correl, true, res.attempts, res.dlq_topic))
        return
    end

    if offsets and (cur == nil or cur > n.offset) then
        offsets[n.partition] = n.offset
    end
    local cok, cerr = conn.consumer:commit_offset(n.topic, n.partition, n.offset)
    if not cok then
        return fail(conn, correl, proto.ERR_INTERNAL, cerr or "nack rewind failed")
    end
    conn:send(proto.encode_nack_ack(correl, false, res.attempts, nil))
end

function M.create_topic(server, conn, correl, payload)
    local c = decode(conn, correl, proto.decode_create_topic, payload)
    if not c then return end
    if c.num_partitions < 1 or c.num_partitions > 1024 then
        return fail(conn, correl, proto.ERR_BAD_FRAME, "num_partitions out of range (1..1024)")
    end
    if not (permitted(conn, acl_m.RES_TOPIC, c.name, acl_m.OP_CREATE)
            or permitted(conn, acl_m.RES_CLUSTER, nil, acl_m.OP_CREATE)) then
        metrics.inc("moonmq_authz_denied_total", 1,
            { resource = acl_m.RES_TOPIC, operation = acl_m.OP_CREATE })
        log:warn("conn=%s user=%s DENIED create on topic %q",
            conn.id_short, conn.username or "?", c.name)
        return fail(conn, correl, proto.ERR_NOT_AUTHORIZED,
            "not authorized: create on topic %q", c.name)
    end
    if not charge(server, conn, correl, c.name, quota_m.DIM_REQUESTS, 1) then return end
    if c.name:sub(1, 2) == "__" then
        return fail(conn, correl, proto.ERR_BAD_FRAME,
            "topic names starting with '__' are reserved for internal use")
    end
    local current = #server.broker:list_topics()
    if current >= server.max_topics then
        return fail(conn, correl, proto.ERR_RATE_LIMITED,
            "topic limit reached (%d)", server.max_topics)
    end
    local _, terr = server.broker:create_topic(c.name, c.num_partitions)
    if terr then
        return fail(conn, correl, proto.ERR_INTERNAL, terr)
    end
    metrics.set("moonmq_topic_count", current + 1)
    conn:send(proto.encode_ok(correl))
end

function M.list_topics(server, conn, correl, _payload)
    local all = server.broker:list_topics()

    if conn.principal then
        local visible = {}
        for _, name in ipairs(all) do
            if permitted(conn, acl_m.RES_TOPIC, name, acl_m.OP_DESCRIBE) then
                visible[#visible + 1] = name
            end
        end
        all = visible
    end

    table.sort(all)
    if #all > server.max_list_topics then
        local truncated = {}
        for i = 1, server.max_list_topics do truncated[i] = all[i] end
        all = truncated
    end
    conn:send(proto.encode_topic_list(correl, all))
end

function M.list_offsets(server, conn, correl, payload)
    local q = decode(conn, correl, proto.decode_list_offsets, payload)
    if not q then return end

    if not authorize(conn, correl, acl_m.RES_TOPIC, q.topic,
                     acl_m.OP_DESCRIBE) then return end
    if not charge(server, conn, correl, q.topic, quota_m.DIM_REQUESTS, 1) then return end

    local topic, terr = server.broker:get_topic(q.topic)
    if not topic then
        return fail(conn, correl, proto.ERR_TOPIC_MISSING, terr or "topic missing")
    end

    local replicator = server.replicator
    local txns       = server.broker.transactions

    local entries = {}
    for id, partition in ipairs(topic.partitions) do
        local latest = partition.offset

        local hwm = latest
        if replicator and replicator:enabled() then
            hwm = replicator:high_watermark(q.topic, id)
        end

        local lso
        if txns then lso = txns:lso(q.topic, id) or latest end

        entries[#entries + 1] = {
            partition      = id,
            earliest       = partition:oldest_offset(),
            latest         = latest,
            high_watermark = hwm,
            lso            = lso,
            local_leader   = server.broker:serves_partition(q.topic, id),
        }
    end

    local for_times
    if q.mode == proto.LIST_OFFSETS_MODE_TIMESTAMP then
        for_times = {}
        for i = 1, #entries do
            local e = entries[i]
            local off = topic.partitions[e.partition]:offset_for_timestamp(q.timestamp)
            for_times[i] = {
                partition = e.partition,
                offset    = off or e.latest,
                found     = off ~= nil,
            }
        end
    end

    conn:send(proto.encode_offsets(correl, entries, for_times))
end

function M.delete_topic(server, conn, correl, payload)
    local c = decode(conn, correl, proto.decode_delete_topic, payload)
    if not c then return end

    if not authorize(conn, correl, acl_m.RES_TOPIC, c.name,
                     acl_m.OP_DELETE) then return end

    if server.broker.is_internal(c.name) then
        return fail(conn, correl, proto.ERR_TOPIC_FORBIDDEN,
            "cannot delete internal topic '%s'", c.name)
    end
    if not server.broker.topic_manager.topics[c.name] then
        return fail(conn, correl, proto.ERR_TOPIC_MISSING, "topic %s does not exist", c.name)
    end

    local ok, derr = server.broker:delete_topic(c.name)
    if not ok then
        return fail(conn, correl, proto.ERR_INTERNAL, derr)
    end
    if derr then
        log:warn("delete_topic %s: %s", c.name, derr)
    end

    metrics.set("moonmq_topic_count", #server.broker:list_topics())
    log:info("topic '%s' deleted", c.name)
    conn:send(proto.encode_ok(correl))
end

function M.describe_topic(server, conn, correl, payload)
    local c = decode(conn, correl, proto.decode_describe_topic, payload)
    if not c then return end

    if not authorize(conn, correl, acl_m.RES_TOPIC, c.name,
                     acl_m.OP_DESCRIBE) then return end
    if not charge(server, conn, correl, c.name, quota_m.DIM_REQUESTS, 1) then return end

    local desc, derr = server.broker:describe_topic(c.name)
    if not desc then
        return fail(conn, correl, proto.ERR_TOPIC_MISSING, derr or "topic missing")
    end

    conn:send(proto.encode_topic_description(
        correl, desc.name, desc.num_partitions, desc.config))
end

function M.alter_topic_config(server, conn, correl, payload)
    local c = decode(conn, correl, proto.decode_alter_topic_config, payload)
    if not c then return end

    if not authorize(conn, correl, acl_m.RES_TOPIC, c.name,
                     acl_m.OP_ALTER) then return end

    if server.broker.is_internal(c.name) then
        return fail(conn, correl, proto.ERR_TOPIC_FORBIDDEN,
            "cannot reconfigure internal topic '%s'", c.name)
    end
    if not server.broker.topic_manager.topics[c.name] then
        return fail(conn, correl, proto.ERR_TOPIC_MISSING, "topic %s does not exist", c.name)
    end

    local applied, aerr = server.broker:alter_topic_config(c.name, c.config)
    if not applied then
        return fail(conn, correl, proto.ERR_INVALID_CONFIG, aerr)
    end

    local keys = {}
    for k in pairs(applied) do keys[#keys + 1] = k end
    table.sort(keys)
    if #keys > 0 then
        log:info("topic '%s' config altered: %s", c.name, table.concat(keys, ","))
    end
    conn:send(proto.encode_ok(correl))
end

function M.list_groups(server, conn, correl, _payload)
    local groups = server.coordinator:list()

    if conn.principal then
        local visible = {}
        for _, g in ipairs(groups) do
            if permitted(conn, acl_m.RES_GROUP, g.group_id, acl_m.OP_DESCRIBE) then
                visible[#visible + 1] = g
            end
        end
        groups = visible
    end

    conn:send(proto.encode_group_list(correl, groups))
end

function M.describe_group(server, conn, correl, payload)
    local c = decode(conn, correl, proto.decode_describe_group, payload)
    if not c then return end

    if not authorize(conn, correl, acl_m.RES_GROUP, c.group_id,
                     acl_m.OP_DESCRIBE) then return end
    if not charge(server, conn, correl, nil, quota_m.DIM_REQUESTS, 1) then return end

    local desc, derr = server.coordinator:describe(c.group_id)
    if not desc then
        return fail(conn, correl, proto.ERR_GROUP_MISSING, derr or "group missing")
    end

    conn:send(proto.encode_group_description(correl, desc))
end

function M.delete_group(server, conn, correl, payload)
    local c = decode(conn, correl, proto.decode_delete_group, payload)
    if not c then return end

    if not authorize(conn, correl, acl_m.RES_GROUP, c.group_id,
                     acl_m.OP_DELETE) then return end

    local n, derr, not_empty = server.coordinator:delete(c.group_id)
    if not n then
        local code = not_empty and proto.ERR_GROUP_NOT_EMPTY
            or proto.ERR_GROUP_MISSING
        return fail(conn, correl, code, derr)
    end

    log:info("group '%s' deleted (%d committed offset(s) cleared)", c.group_id, n)
    conn:send(proto.encode_ok(correl))
end

function M.join_group(server, conn, correl, payload)
    local j = decode(conn, correl, proto.decode_join_group, payload)
    if not j then return end
    if #j.topics == 0 then
        return fail(conn, correl, proto.ERR_BAD_FRAME, "join_group requires at least one topic")
    end
    if not authorize(conn, correl, acl_m.RES_GROUP, j.group_id,
                     acl_m.OP_READ) then return end
    for _, topic in ipairs(j.topics) do
        if not authorize(conn, correl, acl_m.RES_TOPIC, topic,
                         acl_m.OP_READ) then return end
    end
    if not charge(server, conn, correl, nil, quota_m.DIM_REQUESTS, 1) then return end

    if conn.group_id and conn.group_id ~= j.group_id then
        return fail(conn, correl, proto.ERR_GROUP_CONFLICT,
            "connection already in group %s", conn.group_id)
    end

    local member_id = j.member_id
    if member_id == "" then
        member_id = conn.member_id or conn.id_short
    end

    local assignment, jerr, jcode =
        server.coordinator:join(j.group_id, member_id, j.topics)
    if not assignment then
        local code = proto.ERR_INTERNAL
        if jcode == "limit" then
            code = proto.ERR_RATE_LIMITED
        elseif jcode == "topic" then
            code = proto.ERR_TOPIC_MISSING
        end
        return fail(conn, correl, code, jerr or "join failed")
    end

    conn.group_id  = j.group_id
    conn.member_id = member_id
    server.coordinator:apply_assignment(conn)
    log:info("conn=%s joined group=%s member=%s",
        conn.id_short, j.group_id, member_id)
    conn:send(proto.encode_group_assignment(correl, member_id, assignment))
end

function M.leave_group(server, conn, correl, payload)
    local l = decode(conn, correl, proto.decode_leave_group, payload)
    if not l then return end
    if conn.group_id ~= l.group_id then
        return fail(conn, correl, proto.ERR_GROUP_MEMBER_UNKNOWN, "not a member of this group")
    end

    local ok = server.coordinator:leave(l.group_id, conn.member_id)
    if not ok then
        return fail(conn, correl, proto.ERR_GROUP_MEMBER_UNKNOWN, "not a member of this group")
    end
    log:info("conn=%s left group=%s member=%s",
        conn.id_short, l.group_id, conn.member_id)
    conn.group_id  = nil
    conn.member_id = nil
    conn:send(proto.encode_ok(correl))
end

function M.group_heartbeat(server, conn, correl, payload)
    local h = decode(conn, correl, proto.decode_group_heartbeat, payload)
    if not h then return end
    if conn.group_id ~= h.group_id then
        return fail(conn, correl, proto.ERR_GROUP_MEMBER_UNKNOWN, "not a member of this group")
    end

    local ok, herr = server.coordinator:heartbeat(h.group_id, conn.member_id)
    if not ok then
        return fail(conn, correl, proto.ERR_GROUP_MEMBER_UNKNOWN, herr or "unknown member")
    end
    conn:send(proto.encode_ok(correl))
end

function M.begin_txn(server, conn, correl, _payload)
    if not conn.producer_name then
        return fail(conn, correl, proto.ERR_INVALID_TXN_STATE,
            "transactions require a durable producer (producer_name in INIT_PRODUCER_ID)")
    end
    local ok, err, code = server.broker.transactions:begin(
        conn.producer_name, conn.pid, conn.epoch)
    if not ok then
        return fail(conn, correl, txn_err_code(code), err)
    end
    conn.in_txn = true
    log:info("conn=%s began txn=%s epoch=%d", conn.id_short, conn.producer_name, conn.epoch)
    conn:send(proto.encode_ok(correl))
end

function M.end_txn(server, conn, correl, payload)
    -- A transaction left PREPARE_* by a failed finish outlives the session
    -- that began it; the coordinator tells such a producer to "retry
    -- END_TXN", so a reconnected session must be allowed to.
    local resumable = conn.producer_name
        and server.broker.transactions:has_unresolved(conn.producer_name)
    if not conn.producer_name or (not conn.in_txn and not resumable) then
        return fail(conn, correl, proto.ERR_INVALID_TXN_STATE, "no transaction in progress")
    end
    local e, derr = proto.decode_end_txn(payload)
    if not e then
        return fail(conn, correl, proto.ERR_BAD_FRAME, derr)
    end
    local ok, err, code = server.broker.transactions:end_txn(
        conn.producer_name, conn.pid, conn.epoch, e.commit)
    if not ok then
        return fail(conn, correl, txn_err_code(code), err)
    end
    conn.in_txn = false
    log:info("conn=%s %s txn=%s", conn.id_short,
        e.commit and "committed" or "aborted", conn.producer_name)
    conn:send(proto.encode_ok(correl))
end

function M.txn_offset_commit(server, conn, correl, payload)
    if not conn.in_txn or not conn.producer_name then
        return fail(conn, correl, proto.ERR_INVALID_TXN_STATE, "no transaction in progress")
    end
    local t, derr = proto.decode_txn_offset_commit(payload)
    if not t then
        return fail(conn, correl, proto.ERR_BAD_FRAME, derr)
    end
    if not authorize(conn, correl, acl_m.RES_GROUP, t.group,
                     acl_m.OP_READ) then return end
    for _, o in ipairs(t.offsets) do
        if not authorize(conn, correl, acl_m.RES_TOPIC, o.topic,
                         acl_m.OP_READ) then return end
    end

    local ok, err, code = server.broker.transactions:add_offsets(
        conn.producer_name, conn.pid, conn.epoch, t.group, t.offsets)
    if not ok then
        return fail(conn, correl, txn_err_code(code), err)
    end
    conn:send(proto.encode_ok(correl))
end

function M.goodbye(_server, conn, _correl, _payload)
    conn:close(Connection.REASON_CLIENT_GOODBYE)
end

M.BY_OP = {
    [proto.OP_HELLO]              = M.hello,
    [proto.OP_AUTH]               = M.auth,
    [proto.OP_AUTH_SCRAM]         = M.auth_scram,
    [proto.OP_AUTH_SCRAM_FINAL]   = M.auth_scram_final,
    [proto.OP_IDENTIFY_CLIENT]    = M.identify_client,
    [proto.OP_PRODUCE]            = M.produce,
    [proto.OP_PRODUCE_BATCH]      = M.produce_batch,
    [proto.OP_INIT_PRODUCER_ID]   = M.init_producer_id,
    [proto.OP_PRODUCE_IDEMPOTENT] = M.produce_idempotent,
    [proto.OP_SUBSCRIBE]          = M.subscribe,
    [proto.OP_FETCH]              = M.fetch,
    [proto.OP_COMMIT]             = M.commit,
    [proto.OP_NACK]               = M.nack,
    [proto.OP_CREATE_TOPIC]       = M.create_topic,
    [proto.OP_LIST_TOPICS]        = M.list_topics,
    [proto.OP_LIST_OFFSETS]       = M.list_offsets,
    [proto.OP_DELETE_TOPIC]       = M.delete_topic,
    [proto.OP_DESCRIBE_TOPIC]     = M.describe_topic,
    [proto.OP_ALTER_TOPIC_CONFIG] = M.alter_topic_config,
    [proto.OP_LIST_GROUPS]        = M.list_groups,
    [proto.OP_DESCRIBE_GROUP]     = M.describe_group,
    [proto.OP_DELETE_GROUP]       = M.delete_group,
    [proto.OP_JOIN_GROUP]         = M.join_group,
    [proto.OP_LEAVE_GROUP]        = M.leave_group,
    [proto.OP_GROUP_HEARTBEAT]    = M.group_heartbeat,
    [proto.OP_BEGIN_TXN]          = M.begin_txn,
    [proto.OP_END_TXN]            = M.end_txn,
    [proto.OP_TXN_OFFSET_COMMIT]  = M.txn_offset_commit,
    [proto.OP_GOODBYE]            = M.goodbye,
}

return M
