local json    = require("dkjson")
local fs_m    = require("src.io.fs")

local FILE_NAME = "cluster-assignments.json"

local Assignments = {}
Assignments.__index = Assignments

local function key(topic, partition)
    return topic .. "\0" .. tostring(partition)
end

function Assignments.new(data_dir, self_id)
    assert(type(data_dir) == "string", "data_dir must be a string")
    assert(type(self_id) == "string", "self_id must be a string")

    local self = setmetatable({
        path    = fs_m.join_path(data_dir, FILE_NAME),
        self_id = self_id,
        map     = {},
    }, Assignments)

    local lerr = self:_load()
    if lerr then return nil, lerr end
    return self
end

function Assignments:_load()
    local f = io.open(self.path, "rb")
    if not f then return nil end
    local body = f:read("*a") or ""
    f:close()
    if body == "" then return nil end

    local parsed, _, perr = json.decode(body)
    if type(parsed) ~= "table" then
        return string.format("%s: %s", self.path, tostring(perr or "not a JSON object"))
    end
    for _, e in ipairs(parsed.entries or {}) do
        if type(e.topic) == "string" and type(e.partition) == "number"
            and type(e.owner) == "string" then
            self.map[key(e.topic, e.partition)] = e.owner
        end
    end
    return nil
end

function Assignments:_save()
    local entries = {}
    for k, owner in pairs(self.map) do
        local topic, partition = k:match("^(.*)%z(%d+)$")
        entries[#entries + 1] = {
            topic = topic, partition = tonumber(partition), owner = owner,
        }
    end
    table.sort(entries, function(a, b)
        if a.topic ~= b.topic then return a.topic < b.topic end
        return a.partition < b.partition
    end)

    return fs_m.atomic_write(self.path,
        json.encode({ entries = entries }, { indent = true }))
end

function Assignments:owner(topic, partition)
    return self.map[key(topic, partition)] or self.self_id
end

function Assignments:owned_by_self(topic, partition)
    return self:owner(topic, partition) == self.self_id
end

function Assignments:set_owner(topic, partition, owner)
    assert(type(topic) == "string", "topic must be a string")
    assert(type(partition) == "number", "partition must be a number")
    assert(type(owner) == "string", "owner must be a string")

    local k = key(topic, partition)
    local prev = self.map[k]
    if prev == owner then return true end
    self.map[k] = owner

    local ok, err = self:_save()
    if not ok then
        self.map[k] = prev
        return nil, string.format("persist assignments: %s", tostring(err))
    end
    return true
end

function Assignments:replace(entries)
    assert(type(entries) == "table", "entries must be a table")

    local map = {}
    for _, e in ipairs(entries) do
        if type(e.topic) == "string" and type(e.partition) == "number"
            and type(e.owner) == "string" then
            map[key(e.topic, e.partition)] = e.owner
        end
    end

    local prev = self.map
    self.map = map
    local ok, err = self:_save()
    if not ok then
        self.map = prev
        return nil, string.format("persist assignments: %s", tostring(err))
    end
    return true
end

function Assignments:entries()
    local out = {}
    for k, owner in pairs(self.map) do
        local topic, partition = k:match("^(.*)%z(%d+)$")
        out[#out + 1] = { topic = topic, partition = tonumber(partition), owner = owner }
    end
    return out
end

Assignments.FILE_NAME = FILE_NAME
return Assignments
