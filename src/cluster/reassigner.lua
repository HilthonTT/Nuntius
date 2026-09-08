local Action  = require("src.autobalancer.common.action")
local metrics = require("src.metrics")
local log     = require("src.log.logger").get("reassigner")

local ActionType = Action.ActionType

local DEFAULT_BATCH_BYTES = 256 * 1024

local Reassigner = {}
Reassigner.__index = Reassigner

function Reassigner.new(opts)
    return setmetatable({
        broker      = assert(opts.broker, "broker required"),
        assignments = assert(opts.assignments, "assignments required"),
        peers       = assert(opts.peers, "peers required"),
        self_id     = assert(opts.self_id, "self_id required"),
        reactor     = opts.reactor,
        raft_commit = opts.raft_commit,
        batch_bytes = opts.batch_bytes or DEFAULT_BATCH_BYTES,
    }, Reassigner)
end

function Reassigner:_set_owner(topic_name, partition_id, owner)
    if self.raft_commit then
        return self.raft_commit(topic_name, partition_id, owner)
    end
    return self.assignments:set_owner(topic_name, partition_id, owner)
end

local function start_offset(partition)
    local segs = partition.segments
    if type(segs) == "table" and segs[1] and type(segs[1].base_offset) == "number" then
        return segs[1].base_offset
    end
    return 0
end

function Reassigner:_copy_range(peer, topic_name, partition, from)
    local msg_m = require("src.record.message")
    local off = from
    while off < partition.offset do
        local batch, batch_bytes = {}, 0
        while off < partition.offset and batch_bytes < self.batch_bytes do
            local msg, next_offset, rerr = partition:read_message(off)
            if not msg then
                return nil, string.format("read %s/partition-%d @%d: %s",
                    topic_name, partition.id, off, tostring(rerr))
            end
            local bytes, serr = msg_m.serialize_message(msg)
            if not bytes then
                return nil, string.format("serialize @%d: %s", off, tostring(serr))
            end
            batch[#batch + 1] = bytes
            batch_bytes = batch_bytes + #bytes
            off = next_offset
        end

        local _, aerr = peer:append(topic_name, partition.id, table.concat(batch))
        if aerr then return nil, aerr end

        if self.reactor then self.reactor:sleep(0) end
    end
    return off
end

function Reassigner:_move(topic_name, partition_id, dest_id)
    local peer = self.peers[dest_id]
    if not peer then
        return nil, string.format("unknown dest broker %q", tostring(dest_id))
    end
    if not self.assignments:owned_by_self(topic_name, partition_id) then
        return nil, string.format("%s/partition-%d is not owned by this broker",
            topic_name, partition_id)
    end

    local topic, terr = self.broker:get_topic(topic_name)
    if not topic then return nil, terr end
    local partition = topic.partitions[partition_id]
    if not partition then
        return nil, string.format("no local partition %s/partition-%d",
            topic_name, partition_id)
    end

    local ok, err = peer:ensure_topic(topic_name, #topic.partitions)
    if not ok then return nil, err end

    local dest_leo, derr = peer:leo(topic_name, partition_id)
    if not dest_leo then return nil, derr end
    if dest_leo ~= 0 then
        return nil, string.format(
            "dest %s already has %d bytes in %s/partition-%d; refusing to append a mix",
            dest_id, dest_leo, topic_name, partition_id)
    end

    local from = start_offset(partition)
    if from > 0 then
        log:warn("%s/partition-%d: head cleaned up to %d; dest offsets will start at 0",
            topic_name, partition_id, from)
    end

    local stop = metrics.timer("moonmq_reassign_duration_seconds",
        { topic = topic_name })
    local copied_to, cerr = self:_copy_range(peer, topic_name, partition, from)
    if not copied_to then stop(); return nil, cerr end

    local fok, ferr = self:_set_owner(topic_name, partition_id, dest_id)
    if not fok then stop(); return nil, ferr end

    local drained_to, drr = self:_copy_range(peer, topic_name, partition, copied_to)
    if not drained_to then
        self:_set_owner(topic_name, partition_id, self.self_id)
        stop()
        return nil, string.format("tail drain failed (ownership rolled back): %s", drr)
    end

    if self.broker.offsets and peer.push_offsets then
        local snapshot = self.broker.offsets:offsets_for_partition(
            topic_name, partition_id)
        if from > 0 then
            -- Source bytes [from, LEO) were copied to dest [0, LEO-from);
            -- committed offsets are byte positions and must shift with them.
            for group, offset in pairs(snapshot) do
                snapshot[group] = math.max(0, offset - from)
            end
        end
        if next(snapshot) ~= nil then
            local applied, oerr = peer:push_offsets(topic_name, partition_id, snapshot)
            if applied then
                log:info("migrated %d committed offset(s) for %s/partition-%d -> %s",
                    applied, topic_name, partition_id, dest_id)
            else
                log:error("offset migration for %s/partition-%d -> %s failed: %s "
                    .. "(groups resume from their configured start on dest)",
                    topic_name, partition_id, dest_id, tostring(oerr))
            end
        end
    end

    local cok, coerr = true, nil
    if not self.raft_commit then
        cok, coerr = peer:set_owner(topic_name, partition_id, dest_id)
    end
    stop()
    if not cok then
        log:warn("dest %s did not confirm ownership of %s/partition-%d: %s "
            .. "(routing here already forwards; dest treats unlisted partitions as its own)",
            dest_id, topic_name, partition_id, tostring(coerr))
    end

    metrics.inc("moonmq_reassign_partitions_total", 1, { dest = dest_id })
    metrics.inc("moonmq_reassign_bytes_total", drained_to - from, { dest = dest_id })
    log:info("moved %s/partition-%d -> %s (%d bytes)",
        topic_name, partition_id, dest_id, drained_to - from)
    return true
end

function Reassigner:execute(actions)
    local skipped = {}
    for _, action in ipairs(actions) do
        if action.src_broker_id ~= self.self_id then
            skipped[#skipped + 1] = action
            log:warn("skipping non-local action: %s", action:pretty())
        elseif action.action_type == ActionType.MOVE then
            local ok, err = self:_move(
                action.src_topic.name, action.src_partition, action.dest_broker_id)
            if not ok then return nil, err, skipped end
        elseif action.action_type == ActionType.SWAP then
            local ok, err = self:_move(
                action.src_topic.name, action.src_partition, action.dest_broker_id)
            if not ok then return nil, err, skipped end
            log:warn("SWAP executed as one-way MOVE (counterpart is on %s): %s",
                action.dest_broker_id, action:pretty())
        end
    end
    return true, nil, skipped
end

return Reassigner
