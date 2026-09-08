local b64  = require("src.core.base64")
local sha2 = require("src.vendor.sha2")
local log  = require("src.log.logger").get("tls")

local M = {}

local ssl_ok, ssl = pcall(require, "ssl")
if not ssl_ok then ssl = nil end

M.available = ssl ~= nil

function M.version()
    return ssl and (ssl._VERSION or "unknown") or nil
end

local DEFAULT_OPTIONS  = { "all", "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1" }
local DEFAULT_PROTOCOL = "any"

local DEFAULT_HANDSHAKE_TIMEOUT = 10

M.DEFAULT_HANDSHAKE_TIMEOUT = DEFAULT_HANDSHAKE_TIMEOUT

local function readable(path)
    local f = io.open(path, "rb")
    if not f then return false end
    f:close()
    return true
end

local SYSTEM_CA_FILES = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
}

local function system_ca_file()
    for _, path in ipairs(SYSTEM_CA_FILES) do
        if readable(path) then return path end
    end
    return nil
end

local CBIND_MODES = { disabled = true, preferred = true, required = true }

M.CBIND_TYPE = "tls-server-end-point"

function M.der_from_pem(pem)
    if type(pem) ~= "string" then return nil, "certificate is not a string" end
    local body = pem:match(
        "%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-(.-)%-%-%-%-%-END CERTIFICATE%-%-%-%-%-")
    if not body then return nil, "no PEM certificate found" end
    return b64.decode((body:gsub("%s", "")))
end

function M.endpoint_hash_from_pem(pem)
    local der, derr = M.der_from_pem(pem)
    if not der then return nil, derr end
    return sha2.hex_to_bin(sha2.sha256(der))
end

local function endpoint_hash_from_file(path)
    local f = io.open(path, "rb")
    if not f then return nil, string.format("cannot read %q", path) end
    local pem = f:read("*a") or ""
    f:close()
    return M.endpoint_hash_from_pem(pem)
end

function M.peer_endpoint_hash(sock)
    if type(sock) ~= "table" and type(sock) ~= "userdata" then return nil end
    if type(sock.getpeercertificate) ~= "function" then return nil end
    local ok, cert = pcall(sock.getpeercertificate, sock)
    if not ok or not cert or type(cert.pem) ~= "function" then return nil end
    local got, pem = pcall(cert.pem, cert)
    if not got or type(pem) ~= "string" then return nil end
    local hash = M.endpoint_hash_from_pem(pem)
    return hash
end

local function copy(list)
    local out = {}
    for i = 1, #list do out[i] = list[i] end
    return out
end

local function field(block, ...)
    for i = 1, select("#", ...) do
        local key = select(i, ...)
        if block[key] ~= nil then return block[key] end
    end
    return nil
end

local function build(block, where, mode)
    if block == true then block = { Enabled = true } end
    if type(block) ~= "table" then return nil, nil end
    if field(block, "Enabled", "enabled") == false then return nil, nil end

    local params = {
        mode     = mode,
        protocol = field(block, "Protocol", "protocol") or DEFAULT_PROTOCOL,
        options  = copy(DEFAULT_OPTIONS),
    }

    local cert = field(block, "CertFile", "certfile", "Certificate", "certificate")
    local key  = field(block, "KeyFile", "keyfile", "Key", "key")
    local ca   = field(block, "CaFile", "cafile", "CaCert", "cacert")
    local capath = field(block, "CaPath", "capath")

    if mode == "server" then
        if not cert or cert == "" or not key or key == "" then
            return nil, string.format(
                "%s: a TLS listener needs both CertFile and KeyFile", where)
        end
    end

    if cert and cert ~= "" then
        if not readable(cert) then
            return nil, string.format("%s: cannot read CertFile %q", where, cert)
        end
        params.certificate = cert
    end
    if key and key ~= "" then
        if not readable(key) then
            return nil, string.format("%s: cannot read KeyFile %q", where, key)
        end
        params.key = key
    end
    if ca and ca ~= "" then
        if not readable(ca) then
            return nil, string.format("%s: cannot read CaFile %q", where, ca)
        end
        params.cafile = ca
    end

    if capath and capath ~= "" then
        params.capath = capath
    end

    local ciphers = field(block, "Ciphers", "ciphers")
    if ciphers and ciphers ~= "" then
        params.ciphers = ciphers
    end

    local verify = field(block, "Verify", "verify")
    if verify == nil and field(block, "Insecure", "insecure") == true then
        verify = "none"
    end
    verify = tostring(verify or (mode == "client" and "peer" or "none")):lower()
    if verify == "none" then
        params.verify = { "none" }
    elseif verify == "peer" then
        params.verify = { "peer" }
    elseif verify == "required" then
        params.verify = { "peer", "fail_if_no_peer_cert" }
    else
        return nil, string.format(
            "%s: Verify must be none, peer or required (got %q)", where, verify)
    end

    if verify ~= "none" and not params.cafile and not params.capath then
        local system = mode == "client" and system_ca_file() or nil
        if system then
            params.cafile = system
        else
            return nil, string.format(
                "%s: Verify=%q needs a CaFile (or CaPath) to validate against",
                where, verify)
        end
    end

    local timeout = field(block, "HandshakeTimeout", "handshake_timeout")
                    or DEFAULT_HANDSHAKE_TIMEOUT
    if type(timeout) ~= "number" or timeout <= 0 then
        return nil, string.format("%s: HandshakeTimeout must be a positive number", where)
    end

    local cbind = field(block, "ChannelBinding", "channel_binding")
    cbind = tostring(cbind or "preferred"):lower()
    if not CBIND_MODES[cbind] then
        return nil, string.format(
            "%s: ChannelBinding must be disabled, preferred or required (got %q)",
            where, cbind)
    end

    local endpoint_hash
    if mode == "server" and cbind ~= "disabled" then
        local hash, herr = endpoint_hash_from_file(params.certificate)
        if hash then
            endpoint_hash = hash
        elseif cbind == "required" then
            return nil, string.format(
                "%s: ChannelBinding=required needs a PEM CertFile: %s",
                where, tostring(herr))
        else
            log:warn("%s: channel binding is off, CertFile %q is not PEM: %s",
                where, tostring(params.certificate), tostring(herr))
        end
    end

    return {
        params            = params,
        handshake_timeout = timeout,
        verify            = verify,
        server_name       = field(block, "ServerName", "server_name"),
        channel_binding   = cbind,
        endpoint_hash     = endpoint_hash,
    }, nil
end

function M.server_config(block, where)
    return build(block, where or "Tls", "server")
end

function M.client_config(block, where)
    return build(block, where or "Tls", "client")
end

function M.require_available(where)
    if M.available then return true end
    return nil, string.format(
        "%s: TLS is configured but luasec is not installed "
        .. "(luarocks install luasec)", where or "Tls")
end

function M.wrap(sock, params)
    if not ssl then return nil, "luasec not installed" end
    return ssl.wrap(sock, params)
end

function M.set_sni(sock, host)
    if type(sock.sni) == "function" and type(host) == "string" and host ~= "" then
        pcall(sock.sni, sock, host)
    end
end

function M.check_hostname(sock, host)
    if type(sock.getpeercertificate) ~= "function" then return true end
    local ok, cert = pcall(sock.getpeercertificate, sock)
    if not ok or not cert then
        return false, "peer presented no certificate"
    end
    if type(cert.validat) ~= "function" then return true end
    local dns_names, ip_names, common_names = {}, {}, {}

    local function collect(into, value)
        if type(value) == "string" then
            into[#into + 1] = value
        elseif type(value) == "table" then
            for _, entry in ipairs(value) do into[#into + 1] = tostring(entry) end
        end
    end

    local ok_ext, extensions = pcall(cert.extensions, cert)
    if ok_ext and type(extensions) == "table" then
        local san = extensions["2.5.29.17"]
        if type(san) == "table" then
            collect(dns_names, san.dNSName)
            collect(ip_names, san.iPAddress)
        end
    end
    local ok_sub, subject = pcall(cert.subject, cert)
    if ok_sub and type(subject) == "table" then
        for _, entry in ipairs(subject) do
            if entry.name == "commonName" or entry.oid == "2.5.4.3" then
                common_names[#common_names + 1] = tostring(entry.value)
            end
        end
    end

    local is_ip = host:find(":", 1, true) ~= nil
                  or host:match("^%d+%.%d+%.%d+%.%d+$") ~= nil

    local candidates
    if is_ip then
        candidates = ip_names
    elseif #dns_names > 0 then
        candidates = dns_names
    else
        candidates = common_names
    end

    local target = host:lower()
    for _, raw_name in ipairs(candidates) do
        local name = raw_name:lower()
        if name == target then return true end
        if not is_ip then
            local suffix = name:match("^%*(%.[^%.]+%..+)$")
            if suffix and #target > #suffix then
                local head = target:sub(1, #target - #suffix)
                if target:sub(-#suffix) == suffix and not head:find("%.") then
                    return true
                end
            end
        end
    end

    local presented = {}
    for _, n in ipairs(dns_names)    do presented[#presented + 1] = n end
    for _, n in ipairs(ip_names)     do presented[#presented + 1] = n end
    for _, n in ipairs(common_names) do presented[#presented + 1] = n end

    return false, string.format("certificate is not valid for %q (presented: %s)",
        host, #presented > 0 and table.concat(presented, ", ") or "no names")
end

function M.connect_handshake(sock, cfg, host, timeout)
    local wrapped, werr = M.wrap(sock, cfg.params)
    if not wrapped then
        pcall(function() sock:close() end)
        return nil, werr or "tls wrap failed"
    end

    local server_name = cfg.server_name or host
    M.set_sni(wrapped, server_name)
    wrapped:settimeout(timeout or cfg.handshake_timeout)

    local socket_m = require("socket")
    local deadline = socket_m.gettime() + (cfg.handshake_timeout or DEFAULT_HANDSHAKE_TIMEOUT)

    while true do
        local ok, herr = wrapped:dohandshake()
        if ok then break end

        if herr ~= "timeout" and herr ~= "wantread" and herr ~= "wantwrite" then
            pcall(function() wrapped:close() end)
            return nil, string.format("tls handshake failed: %s", tostring(herr))
        end
        if socket_m.gettime() > deadline then
            pcall(function() wrapped:close() end)
            return nil, "tls handshake deadline exceeded"
        end
    end

    if cfg.verify ~= "none" then
        local vok, verr = M.check_hostname(wrapped, server_name)
        if not vok then
            pcall(function() wrapped:close() end)
            return nil, verr
        end
    end

    return wrapped, nil
end

function M.http_create(params, timeout, host_override)
    local socket = require("socket")
    return function()
        local conn = { sock = socket.tcp() }
        if not conn.sock then return nil, "socket.tcp failed" end
        conn.sock:settimeout(timeout)

        function conn:settimeout()
            return self.sock:settimeout(timeout)
        end

        function conn:close()
            return self.sock:close()
        end

        function conn:connect(host, port)
            local ok, err = self.sock:connect(host, port)
            if not ok then return nil, err end

            local wrapped, werr = M.wrap(self.sock, params)
            if not wrapped then return nil, werr end
            self.sock = wrapped
            M.set_sni(self.sock, host_override or host)
            self.sock:settimeout(timeout)

            local hok, herr = self.sock:dohandshake()
            if not hok then return nil, herr end

            if params.verify and params.verify[1] ~= "none" then
                local vok, verr = M.check_hostname(self.sock, host_override or host)
                if not vok then return nil, verr end
            end

            local mt = getmetatable(self.sock).__index
            for name, method in pairs(mt) do
                if type(method) == "function" and name ~= "connect"
                   and name ~= "settimeout" and name ~= "close" then
                    self[name] = function(s, ...) return method(s.sock, ...) end
                end
            end
            return 1
        end

        return conn
    end
end

function M.describe(cfg)
    if not cfg then return "plaintext" end
    return string.format("TLS (%s, verify=%s)",
        cfg.params.protocol, cfg.verify)
end

function M.log_unavailable()
    if not M.available then
        log:debug("luasec not installed; TLS unavailable")
    end
end

return M
