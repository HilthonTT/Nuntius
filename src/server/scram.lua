local sha2   = require("src.vendor.sha2")
local b64    = require("src.core.base64")
local ct     = require("src.core.ct")

local M = {}

M.MECHANISM = "SCRAM-SHA-256"

M.GS2_HEADER  = "n,,"
M.GS2_CBIND   = "biws"
M.CBIND_TYPE  = "tls-server-end-point"

local function hmac_bin(key, msg)
    return sha2.hex_to_bin(sha2.hmac(sha2.sha256, key, msg))
end
M.hmac_bin = hmac_bin

local function h_bin(msg)
    return sha2.hex_to_bin(sha2.sha256(msg))
end
M.h_bin = h_bin

local function xor_bin(a, b)
    if #a ~= #b then return nil end
    local out = {}
    for i = 1, #a do
        out[i] = string.char(a:byte(i) ~ b:byte(i))
    end
    return table.concat(out)
end
M.xor_bin = xor_bin

function M.escape_username(name)
    return (name:gsub("=", "=3D"):gsub(",", "=2C"))
end

function M.unescape_username(name)
    if not name:find("=", 1, true) then return name end

    local out, i, n = {}, 1, #name
    while i <= n do
        local c = name:sub(i, i)
        if c == "=" then
            local seq = name:sub(i + 1, i + 2)
            if seq == "3D" then
                out[#out + 1] = "="
            elseif seq == "2C" then
                out[#out + 1] = ","
            else
                return nil, "invalid escape in username"
            end
            i = i + 3
        else
            out[#out + 1] = c
            i = i + 1
        end
    end
    return table.concat(out)
end

function M.keys_from_salted(salted_password)
    local client_key = hmac_bin(salted_password, "Client Key")
    return h_bin(client_key), hmac_bin(salted_password, "Server Key")
end

function M.nonce(rng_bytes, n)
    return b64.encode(rng_bytes(n or 18))
end

local function parse_fields(str)
    local fields = {}
    for part in str:gmatch("[^,]+") do
        local k, v = part:match("^(%a)=(.*)$")
        if k then
            if fields[k] == nil then fields[k] = v end
        end
    end
    return fields
end


function M.parse_client_first(message)
    if type(message) ~= "string" or #message == 0 then
        return nil, "empty client-first message"
    end

    local cbind_flag = message:sub(1, 1)
    if cbind_flag ~= "n" and cbind_flag ~= "y" and cbind_flag ~= "p" then
        return nil, "malformed gs2 header"
    end

    local comma1 = message:find(",", 1, true)
    if not comma1 then return nil, "malformed gs2 header" end

    local head = message:sub(1, comma1 - 1)
    local cbind_name
    if cbind_flag == "p" then
        cbind_name = head:match("^p=(.+)$")
        if not cbind_name then return nil, "malformed channel-binding flag" end
    elseif head ~= cbind_flag then
        return nil, "malformed gs2 header"
    end
    local comma2 = message:find(",", comma1 + 1, true)
    if not comma2 then return nil, "malformed gs2 header" end

    local authzid = message:sub(comma1 + 1, comma2 - 1)
    if authzid ~= "" then
        return nil, "authzid is not supported"
    end

    local bare = message:sub(comma2 + 1)
    local fields = parse_fields(bare)
    if not fields.n then return nil, "missing username (n=)" end
    if not fields.r or fields.r == "" then return nil, "missing client nonce (r=)" end

    local username, uerr = M.unescape_username(fields.n)
    if not username then return nil, uerr end
    if username == "" then return nil, "empty username" end

    return {
        username   = username,
        nonce      = fields.r,
        bare       = bare,
        gs2        = message:sub(1, comma2),
        cbind_flag = cbind_flag,
        cbind_name = cbind_name,
    }, nil
end

function M.negotiate_cbind(first, cbind_data, mode)
    mode = mode or "preferred"

    if first.cbind_flag == "p" then
        if mode == "disabled" or not cbind_data then
            return nil, "channel binding is not available on this connection"
        end
        if first.cbind_name ~= M.CBIND_TYPE then
            return nil, string.format("unsupported channel-binding type %q",
                tostring(first.cbind_name))
        end
        return cbind_data
    end

    if mode == "required" then
        return nil, "this listener requires SCRAM channel binding"
    end
    if first.cbind_flag == "y" and cbind_data then
        return nil, "channel-binding downgrade detected"
    end
    return ""
end

function M.server_first(combined_nonce, salt, iterations)
    return string.format("r=%s,s=%s,i=%d",
        combined_nonce, b64.encode(salt), iterations)
end

function M.parse_client_final(message)
    if type(message) ~= "string" or #message == 0 then
        return nil, "empty client-final message"
    end

    local fields = parse_fields(message)
    if not fields.c then return nil, "missing channel binding (c=)" end
    if not fields.r then return nil, "missing nonce (r=)" end
    if not fields.p then return nil, "missing proof (p=)" end

    local proof_at = message:find(",p=", 1, true)
    if not proof_at then return nil, "missing proof (p=)" end

    local proof, perr = b64.decode(fields.p)
    if not proof then return nil, perr end

    return {
        cbind         = fields.c,
        nonce         = fields.r,
        proof         = proof,
        without_proof = message:sub(1, proof_at - 1),
    }, nil
end

function M.check_cbind(client_first_gs2, c_field, cbind_data)
    return ct.equal(b64.encode(client_first_gs2 .. (cbind_data or "")), c_field or "")
end

function M.auth_message(client_first_bare, server_first, client_final_without_proof)
    return client_first_bare .. "," .. server_first .. "," .. client_final_without_proof
end

function M.verify_proof(stored_key, auth_message, proof)
    if type(stored_key) ~= "string" or type(proof) ~= "string" then return false end
    local client_signature = hmac_bin(stored_key, auth_message)
    local recovered = xor_bin(proof, client_signature)
    if not recovered then return false end
    return ct.equal(h_bin(recovered), stored_key)
end

function M.server_final(server_key, auth_message)
    return "v=" .. b64.encode(hmac_bin(server_key, auth_message))
end


function M.client_first(username, nonce, cbind_type)
    local gs2 = cbind_type and ("p=" .. cbind_type .. ",,") or M.GS2_HEADER
    local bare = string.format("n=%s,r=%s", M.escape_username(username), nonce)
    return gs2 .. bare, bare, gs2
end

function M.parse_server_first(message, client_nonce)
    if type(message) ~= "string" or #message == 0 then
        return nil, "empty server-first message"
    end

    local fields = parse_fields(message)
    if fields.e then return nil, "server error: " .. fields.e end
    if not fields.r then return nil, "missing nonce (r=)" end
    if not fields.s then return nil, "missing salt (s=)" end
    if not fields.i then return nil, "missing iteration count (i=)" end

    if fields.r:sub(1, #client_nonce) ~= client_nonce or #fields.r <= #client_nonce then
        return nil, "server nonce does not extend the client nonce"
    end

    local salt, serr = b64.decode(fields.s)
    if not salt then return nil, serr end

    local iterations = tonumber(fields.i)
    if not iterations or iterations < 1 or iterations ~= math.floor(iterations) then
        return nil, "invalid iteration count"
    end

    return { nonce = fields.r, salt = salt, iterations = iterations }, nil
end

function M.client_final(salted_password, client_first_bare, server_first,
                       combined_nonce, cbind_input)
    local without_proof = string.format("c=%s,r=%s",
        b64.encode(cbind_input or M.GS2_HEADER), combined_nonce)
    local auth_message  = M.auth_message(client_first_bare, server_first, without_proof)

    local client_key       = hmac_bin(salted_password, "Client Key")
    local stored_key       = h_bin(client_key)
    local client_signature = hmac_bin(stored_key, auth_message)
    local proof            = xor_bin(client_key, client_signature)

    local server_key = hmac_bin(salted_password, "Server Key")
    local expected   = hmac_bin(server_key, auth_message)

    return without_proof .. ",p=" .. b64.encode(proof), expected, auth_message
end

function M.verify_server_final(message, expected_signature)
    if type(message) ~= "string" then return false, "empty server-final message" end

    local fields = parse_fields(message)
    if fields.e then return false, "server rejected: " .. fields.e end
    if not fields.v then return false, "missing server signature (v=)" end

    local got, derr = b64.decode(fields.v)
    if not got then return false, derr end
    if not ct.equal(got, expected_signature) then
        return false, "server signature mismatch"
    end
    return true, nil
end

return M
