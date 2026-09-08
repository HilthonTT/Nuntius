local json = require("dkjson")
local fs_m = require("src.io.fs")

local FILE_NAME = "raft-state.json"

local Store = {}
Store.__index = Store

local function empty_state()
    return {
        current_term = 0,
        voted_for    = nil,
        base_index   = 0,
        base_term    = 0,
        snapshot     = nil,
        entries      = {},
    }
end

Store.empty_state = empty_state

local function sanitize_entry(raw, expected_index)
    if type(raw) ~= "table" then return nil end
    if type(raw.term) ~= "number" or raw.term < 0 then return nil end
    if type(raw.index) ~= "number" or raw.index ~= expected_index then return nil end
    if type(raw.kind) ~= "string" then return nil end
    return {
        term  = raw.term,
        index = raw.index,
        kind  = raw.kind,
        data  = type(raw.data) == "table" and raw.data or {},
    }
end

function Store.new(data_dir)
    assert(type(data_dir) == "string", "data_dir must be a string")
    local self = setmetatable({
        path = fs_m.join_path(data_dir, FILE_NAME),
    }, Store)

    local state, lerr = self:_load()
    if not state then return nil, lerr end
    self.state = state
    return self
end

function Store:_load()
    local f = io.open(self.path, "rb")
    if not f then return empty_state() end
    local body = f:read("*a") or ""
    f:close()
    if body == "" then return empty_state() end

    local parsed, _, perr = json.decode(body)
    if type(parsed) ~= "table" or type(parsed.current_term) ~= "number" then
        return nil, string.format("%s: %s", self.path,
            tostring(perr or "not a JSON object"))
    end

    local state = empty_state()
    state.current_term = parsed.current_term
    state.voted_for    = type(parsed.voted_for) == "string" and parsed.voted_for or nil
    state.base_index   = type(parsed.base_index) == "number" and parsed.base_index or 0
    state.base_term    = type(parsed.base_term) == "number" and parsed.base_term or 0
    state.snapshot     = type(parsed.snapshot) == "table" and parsed.snapshot or nil

    for i, raw in ipairs(parsed.entries or {}) do
        local entry = sanitize_entry(raw, state.base_index + i)
        if not entry then
            return nil, string.format("%s: log entry %d is malformed", self.path, i)
        end
        state.entries[i] = entry
    end
    return state
end

function Store:save(state)
    return fs_m.atomic_write(self.path, json.encode({
        current_term = state.current_term,
        voted_for    = state.voted_for,
        base_index   = state.base_index,
        base_term    = state.base_term,
        snapshot     = state.snapshot,
        entries      = state.entries,
    }, { indent = true }))
end

Store.FILE_NAME = FILE_NAME
return Store
