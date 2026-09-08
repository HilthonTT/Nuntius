local socket = require("socket")
local json   = require("dkjson")
local httpk  = require("src.server.http_kit")
local tls_m  = require("src.io.tls")

local M = {}

local MAX_BODY = 4 * 1024 * 1024

function M.split_address(address)
    local host, port = address:match("^(.*):(%d+)$")
    if not host then return nil, string.format("malformed address %q", address) end
    host = host:gsub("^%[(.*)%]$", "%1")
    return host, tonumber(port)
end

local function dial(reactor, host, port, deadline)
    local sock, serr = socket.tcp()
    if not sock then return nil, tostring(serr) end
    sock:settimeout(0)

    local ok, cerr = sock:connect(host, port)
    while not ok do
        if cerr == "already connected" then break end
        if not (cerr == "timeout" or cerr == "Operation already in progress") then
            pcall(function() sock:close() end)
            return nil, tostring(cerr)
        end
        if not reactor:wait_writable(sock, deadline) then
            pcall(function() sock:close() end)
            return nil, "connect deadline"
        end
        ok, cerr = sock:connect(host, port)
    end
    return sock
end

function M.post(reactor, opts)
    local host, port = M.split_address(opts.address)
    if not host then return nil, port end

    local deadline = socket.gettime() + (opts.timeout or 1)
    local sock, derr = dial(reactor, host, port, deadline)
    if not sock then return nil, derr end

    if opts.tls then
        local secured, terr = reactor:tls_handshake(sock, opts.tls.params, deadline)
        if not secured then return nil, string.format("tls: %s", tostring(terr)) end
        if opts.tls.verify ~= "none" then
            local vok, verr = tls_m.check_hostname(secured, opts.tls.server_name or host)
            if not vok then
                pcall(function() secured:close() end)
                return nil, verr
            end
        end
        sock = secured
    end

    local function done(result, err)
        pcall(function() sock:close() end)
        return result, err
    end

    local body = opts.body or ""
    local head = {
        string.format("POST %s HTTP/1.1", opts.path),
        string.format("Host: %s:%d", host, port),
        "Content-Type: application/json",
        string.format("Content-Length: %d", #body),
        "Connection: close",
    }
    if opts.token then head[#head + 1] = "X-Cluster-Token: " .. opts.token end

    local request = table.concat(head, "\r\n") .. "\r\n\r\n" .. body
    local sok, serr = reactor:send_all(sock, request, deadline)
    if not sok then return done(nil, tostring(serr)) end

    local headers, leftover = httpk.read_headers(reactor, sock, deadline)
    if not headers then return done(nil, tostring(leftover)) end

    local code = tonumber(headers:match("^HTTP/%d%.%d%s+(%d+)"))
    if not code then return done(nil, "malformed HTTP response") end

    local clen = tonumber(httpk.header(headers, "Content%-Length")) or 0
    local text, berr = httpk.read_body(reactor, sock, leftover, clen, deadline, MAX_BODY)
    if not text then return done(nil, tostring(berr)) end

    if code ~= 200 then
        return done(nil, string.format("HTTP %d: %s", code, text))
    end

    local parsed, _, perr = json.decode(text)
    if type(parsed) ~= "table" then
        return done(nil, string.format("invalid JSON: %s", tostring(perr)))
    end
    return done(parsed)
end

return M
