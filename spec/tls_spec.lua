local tls_m   = require("src.io.tls")
local Reactor = require("src.server.reactor")
local socket  = require("socket")
local os_utils = require("src.core.os")

local BASE_DIR = os_utils.IS_WINDOWS and "C:\\Temp\\moonmq_tls_test"
                                      or "/tmp/moonmq_tls_test"

local function rmdir(path)
    if os_utils.IS_WINDOWS then
        os.execute(string.format('rmdir /s /q "%s" 2>nul', path:gsub("/", "\\")))
    else
        os.execute(string.format("rm -rf '%s'", path))
    end
end

local function exists(path)
    local f = io.open(path, "rb")
    if f then f:close(); return true end
    return false
end

local CERT = BASE_DIR .. "/cert.pem"
local KEY  = BASE_DIR .. "/key.pem"
local OTHER_CERT = BASE_DIR .. "/other-cert.pem"
local OTHER_KEY  = BASE_DIR .. "/other-key.pem"

local function generate(cert, key, cn)
    os.execute(string.format(
        "openssl req -x509 -newkey rsa:2048 -nodes -days 2 "
        .. "-subj '/CN=%s' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' "
        .. "-keyout '%s' -out '%s' >/dev/null 2>&1", cn, key, cert))
    return exists(cert) and exists(key)
end

local have_certs = false
if tls_m.available and not os_utils.IS_WINDOWS then
    rmdir(BASE_DIR)
    os.execute(string.format("mkdir -p '%s'", BASE_DIR))
    have_certs = generate(CERT, KEY, "localhost")
                 and generate(OTHER_CERT, OTHER_KEY, "localhost")
end

describe("tls configuration", function()

    it("returns nothing when no block is given", function()
        assert.is_nil((tls_m.server_config(nil, "Server.Tls")))
        assert.is_nil((tls_m.server_config({ Enabled = false }, "Server.Tls")))
        local cfg, err = tls_m.server_config(nil, "Server.Tls")
        assert.is_nil(cfg)
        assert.is_nil(err)
    end)

    it("treats a block with no Enabled key as enabled", function()
        if not have_certs then return end
        local cfg = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "Server.Tls"))
        assert.are.equal(CERT, cfg.params.certificate)
        assert.are.equal("server", cfg.params.mode)
    end)

    it("requires a certificate and key for a listener", function()
        local cfg, err = tls_m.server_config({ Enabled = true }, "Server.Tls")
        assert.is_nil(cfg)
        assert.is_truthy(err:find("CertFile and KeyFile"))
        assert.is_truthy(err:find("Server.Tls"), "the error names the listener")
    end)

    it("rejects files it cannot read", function()
        local cfg, err = tls_m.server_config(
            { CertFile = BASE_DIR .. "/nope.pem", KeyFile = KEY }, "Server.Tls")
        assert.is_nil(cfg)
        assert.is_truthy(err:find("cannot read CertFile"))
    end)

    it("rejects an unknown Verify mode", function()
        if not have_certs then return end
        local cfg, err = tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY, Verify = "sometimes" }, "Server.Tls")
        assert.is_nil(cfg)
        assert.is_truthy(err:find("none, peer or required"))
    end)

    it("refuses to verify with nothing to verify against", function()
        if not have_certs then return end
        local cfg, err = tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY, Verify = "required" }, "Server.Tls")
        assert.is_nil(cfg)
        assert.is_truthy(err:find("CaFile"))
    end)

    it("maps Verify onto luasec's verify flags", function()
        if not have_certs then return end
        local none = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "T"))
        assert.are.same({ "none" }, none.params.verify)

        local peer = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY, CaFile = CERT, Verify = "peer" }, "T"))
        assert.are.same({ "peer" }, peer.params.verify)

        local required = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY, CaFile = CERT,
              Verify = "required" }, "T"))
        assert.are.same({ "peer", "fail_if_no_peer_cert" }, required.params.verify)
    end)

    it("defaults a client to verifying and a server to not demanding", function()
        if not have_certs then return end
        local client = assert(tls_m.client_config({ CaFile = CERT }, "T"))
        assert.are.equal("peer", client.verify)

        local server = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "T"))
        assert.are.equal("none", server.verify)
    end)

    it("accepts insecure as an explicit opt-out", function()
        local cfg = assert(tls_m.client_config({ Insecure = true }, "T"))
        assert.are.equal("none", cfg.verify)
        assert.are.same({ "none" }, cfg.params.verify)
    end)

    it("accepts lowercase keys, for callers configuring in Lua", function()
        if not have_certs then return end
        local cfg = assert(tls_m.client_config(
            { cafile = CERT, verify = "peer", server_name = "localhost" }, "T"))
        assert.are.equal(CERT, cfg.params.cafile)
        assert.are.equal("localhost", cfg.server_name)
    end)

    it("accepts `true` as shorthand, verifying against the system CA store", function()
        local cfg, err = tls_m.client_config(true, "T")
        if not cfg and err and err:find("CaFile") then
            return
        end
        assert.is_truthy(cfg, err)
        assert.are.equal("client", cfg.params.mode)
        assert.are.equal("peer", cfg.verify)
        assert.is_truthy(cfg.params.cafile, "should have found a system CA bundle")
    end)

    it("never falls back to the system store for a listener", function()
        if not have_certs then return end
        local cfg, err = tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY, Verify = "required" }, "T")
        assert.is_nil(cfg)
        assert.is_truthy(err:find("CaFile"))
    end)

    it("excludes the broken protocol versions", function()
        if not have_certs then return end
        local cfg = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "T"))
        local opts = {}
        for _, o in ipairs(cfg.params.options) do opts[o] = true end
        for _, banned in ipairs({ "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1" }) do
            assert.is_true(opts[banned], banned .. " must be disabled")
        end
        assert.are.equal("any", cfg.params.protocol)
    end)

    it("validates the handshake timeout", function()
        if not have_certs then return end
        local cfg, err = tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY, HandshakeTimeout = 0 }, "T")
        assert.is_nil(cfg)
        assert.is_truthy(err:find("HandshakeTimeout"))
    end)

    it("describes a listener for the boot log", function()
        assert.are.equal("plaintext", tls_m.describe(nil))
        if not have_certs then return end
        local cfg = assert(tls_m.server_config({ CertFile = CERT, KeyFile = KEY }, "T"))
        assert.is_truthy(tls_m.describe(cfg):find("TLS"))
        assert.is_truthy(tls_m.describe(cfg):find("verify=none"))
    end)

    it("validates without needing luasec installed", function()
        local ok, err = tls_m.require_available("Server.Tls")
        if tls_m.available then
            assert.is_true(ok)
            assert.is_nil(err)
        else
            assert.is_nil(ok)
            assert.is_truthy(err:find("luasec"))
            assert.is_truthy(err:find("Server.Tls"))
        end

        local cfg, cerr = tls_m.server_config({ Enabled = true }, "Server.Tls")
        assert.is_nil(cfg)
        assert.is_truthy(cerr:find("CertFile and KeyFile"))
    end)
end)

describe("tls hostname verification", function()

    local function fake_sock(dns, ips, cns)
        local cert = {
            validat    = function() return true end,
            extensions = function()
                return { ["2.5.29.17"] = { dNSName = dns, iPAddress = ips } }
            end,
            subject = function()
                local out = {}
                for _, cn in ipairs(cns or {}) do
                    out[#out + 1] =
                        { name = "commonName", oid = "2.5.4.3", value = cn }
                end
                return out
            end,
        }
        return { getpeercertificate = function() return cert end }
    end

    local CASES = {
        { "matches a dNSName SAN",
          { "localhost" }, { "127.0.0.1" }, { "moonmq" }, "localhost", true },

        { "matches an iPAddress SAN when dialled by IP",
          { "localhost" }, { "127.0.0.1" }, { "moonmq" }, "127.0.0.1", true },
        { "matches an IPv6 SAN",
          {}, { "::1" }, {}, "::1", true },

        { "rejects an IP that is not in the SAN",
          { "localhost" }, { "127.0.0.1" }, {}, "10.0.0.1", false },
        { "rejects a name that is not in the SAN",
          { "localhost" }, { "127.0.0.1" }, {}, "evil.example.com", false },
        { "never matches an IP against a dNSName",
          { "localhost" }, {}, {}, "127.0.0.1", false },

        { "ignores the CN when a dNSName SAN is present",
          { "localhost" }, {}, { "moonmq" }, "moonmq", false },
        { "falls back to the CN when there is no SAN",
          {}, {}, { "broker.example.com" }, "broker.example.com", true },

        { "honours a one-label wildcard",
          { "*.example.com" }, {}, {}, "a.example.com", true },
        { "does not let a wildcard span a dot",
          { "*.example.com" }, {}, {}, "a.b.example.com", false },
        { "does not let a wildcard match the bare domain",
          { "*.example.com" }, {}, {}, "example.com", false },
        { "never lets a wildcard match an IP",
          { "*" }, {}, {}, "10.0.0.1", false },

        { "matches names case-insensitively",
          { "LOCALHOST" }, {}, {}, "localhost", true },
    }

    for _, case in ipairs(CASES) do
        local label, dns, ips, cns, host, want = table.unpack(case, 1, 6)
        it(label, function()
            local ok, err = tls_m.check_hostname(fake_sock(dns, ips, cns), host)
            if want then
                assert.is_truthy(ok, err)
            else
                assert.is_falsy(ok)
                assert.is_truthy(err)
                assert.is_truthy(err:find(host, 1, true),
                    "the error names the host that was dialled")
            end
        end)
    end

    it("refuses a peer that presents no certificate at all", function()
        local sock = { getpeercertificate = function() return nil end }
        local ok, err = tls_m.check_hostname(sock, "localhost")
        assert.is_falsy(ok)
        assert.is_truthy(err:find("no certificate"))
    end)
end)

describe("tls http_create", function()
    it("can be closed before connect succeeds", function()
        local conn = tls_m.http_create({ mode = "client" }, 1, "127.0.0.1")()
        assert.is_truthy(conn)
        assert.are.equal("function", type(conn.close))
        assert.are.equal("function", type(conn.connect))
        assert.is_truthy(conn:close())
    end)

    it("reports a refused connection instead of raising", function()
        local http  = require("socket.http")
        local ltn12 = require("ltn12")
        local cfg = assert(tls_m.client_config({ Insecure = true }, "T"))

        local ok, res, err = pcall(http.request, {
            url    = "https://127.0.0.1:1/cluster/ping",
            create = tls_m.http_create(cfg.params, 2, "127.0.0.1"),
            sink   = ltn12.sink.table({}),
        })
        assert.is_true(ok, "an unreachable peer must not raise: " .. tostring(res))
        assert.is_nil(res)
        assert.is_truthy(err)
    end)
end)

describe("tls over the reactor", function()

    if not tls_m.available or not have_certs then
        pending("luasec and openssl are needed for the TLS connection tests")
        return
    end

    local function exchange(server_block, client_block, client_fn, port)
        local reactor = Reactor.new()
        local server_cfg = assert(tls_m.server_config(server_block, "test server"))
        local result, failure

        local _, lerr = reactor:listen("127.0.0.1", port, function(sock)
            local header = reactor:read_exact(sock, 4, socket.gettime() + 5)
            if header then
                local n = string.unpack(">I4", header)
                local body = reactor:read_exact(sock, n, socket.gettime() + 10)
                if body then
                    reactor:send_all(sock, header .. body, socket.gettime() + 10)
                end
            end
            pcall(function() sock:close() end)
        end, { tls = server_cfg })
        assert.is_nil(lerr)

        reactor:spawn(function()
            local ok, err = pcall(function()
                local raw = assert(socket.connect("127.0.0.1", port))
                local cfg = assert(tls_m.client_config(client_block, "test client"))
                local sock, herr = reactor:tls_handshake(
                    raw, cfg.params, socket.gettime() + 5)
                if not sock then
                    result = { handshake_error = tostring(herr) }
                    return
                end
                result = client_fn(reactor, sock)
                pcall(function() sock:close() end)
            end)
            if not ok then failure = err end
            reactor:stop()
        end)

        reactor:spawn(function()
            reactor:sleep(20)
            reactor:stop()
        end)

        reactor:run()
        reactor:shutdown()

        if failure then error(failure) end
        return result
    end

    local function echo_once(payload)
        return function(reactor, sock)
            local ok, err = reactor:send_all(sock,
                string.pack(">I4", #payload) .. payload, socket.gettime() + 10)
            if not ok then return { error = tostring(err) } end
            local header = reactor:read_exact(sock, 4, socket.gettime() + 10)
            if not header then return { error = "no header" } end
            local n = string.unpack(">I4", header)
            local body = reactor:read_exact(sock, n, socket.gettime() + 10)
            return { echoed = body }
        end
    end

    it("completes a handshake and carries data", function()
        local out = exchange(
            { CertFile = CERT, KeyFile = KEY },
            { CaFile = CERT, Verify = "peer" },
            echo_once("hello over tls"), 19301)
        assert.is_nil(out.handshake_error)
        assert.are.equal("hello over tls", out.echoed)
    end)

    it("carries a payload spanning many TLS records", function()
        local payload = string.rep("MoonMQ/", 150000)
        local out = exchange(
            { CertFile = CERT, KeyFile = KEY },
            { CaFile = CERT, Verify = "peer" },
            echo_once(payload), 19302)
        assert.is_nil(out.handshake_error)
        assert.are.equal(#payload, #(out.echoed or ""))
        assert.are.equal(payload, out.echoed)
    end)

    it("refuses a server whose certificate is signed by another CA", function()
        local out = exchange(
            { CertFile = CERT, KeyFile = KEY },
            { CaFile = OTHER_CERT, Verify = "peer" },
            echo_once("should not arrive"), 19303)
        assert.is_truthy(out.handshake_error,
            "an untrusted certificate must fail the handshake")
        assert.is_nil(out.echoed)
    end)

    it("connects to an untrusted server when verification is off", function()
        local out = exchange(
            { CertFile = CERT, KeyFile = KEY },
            { Insecure = true },
            echo_once("dev mode"), 19304)
        assert.is_nil(out.handshake_error)
        assert.are.equal("dev mode", out.echoed)
    end)

    it("refuses a client with no certificate when Verify=required (mTLS)", function()
        local out = exchange(
            { CertFile = CERT, KeyFile = KEY, CaFile = CERT, Verify = "required" },
            { CaFile = CERT, Verify = "peer" },
            echo_once("no client cert"), 19305)

        assert.is_nil(out.echoed,
            "a listener demanding client certs must not carry data without one")
    end)

    it("accepts a client presenting a trusted certificate (mTLS)", function()
        local out = exchange(
            { CertFile = CERT, KeyFile = KEY, CaFile = CERT, Verify = "required" },
            { CaFile = CERT, CertFile = CERT, KeyFile = KEY, Verify = "peer" },
            echo_once("mutual"), 19306)
        assert.is_nil(out.handshake_error)
        assert.are.equal("mutual", out.echoed)
    end)

    it("gives the client the endpoint hash the server binds SCRAM to", function()
        local expected = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "test server")).endpoint_hash
        assert.is_truthy(expected)

        local result = exchange(
            { CertFile = CERT, KeyFile = KEY },
            { CaFile = CERT, Verify = "peer" },
            function(_, sock)
                return { hash = tls_m.peer_endpoint_hash(sock) }
            end, 19310)

        assert.is_truthy(result.hash)
        assert.are.equal(expected, result.hash)
    end)

    it("refuses a plaintext client on a TLS listener", function()
        local reactor = Reactor.new()
        local server_cfg = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "test server"))
        local reached_handler = false

        assert(reactor:listen("127.0.0.1", 19307, function(sock)
            reached_handler = true
            pcall(function() sock:close() end)
        end, { tls = server_cfg }))

        local closed
        reactor:spawn(function()
            local raw = assert(socket.connect("127.0.0.1", 19307))
            raw:settimeout(3)
            raw:send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            local _, err = raw:receive(1)
            closed = err
            raw:close()
            reactor:stop()
        end)
        reactor:spawn(function() reactor:sleep(10); reactor:stop() end)
        reactor:run()
        reactor:shutdown()

        assert.is_false(reached_handler,
            "a failed handshake must never reach the connection handler")
        assert.is_truthy(closed)
    end)

    it("closes the socket when a handshake fails", function()
        local function open_fds()
            local p = io.popen("ls /proc/self/fd 2>/dev/null | wc -l")
            if not p then return nil end
            local n = tonumber(p:read("*a")) or 0
            p:close()
            return n
        end

        if not open_fds() then return end

        local reactor = Reactor.new()
        local server_cfg = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "test server"))
        assert(reactor:listen("127.0.0.1", 19309, function(sock)
            pcall(function() sock:close() end)
        end, { tls = server_cfg }))

        local attempts, before = 25, nil
        reactor:spawn(function()
            for i = 1, attempts do
                local raw = socket.connect("127.0.0.1", 19309)
                if raw then
                    raw:settimeout(0.2)
                    raw:send("not a client hello\n")
                    raw:receive(1)
                    raw:close()
                end
                reactor:sleep(0.02)
                if i == 5 then before = open_fds() end
            end
            reactor:sleep(0.2)
            reactor:stop()
        end)
        reactor:spawn(function() reactor:sleep(15); reactor:stop() end)
        reactor:run()

        local after = open_fds()
        reactor:shutdown()

        assert.is_truthy(before)
        assert.is_true(after - before < 5,
            string.format("descriptors grew by %d across %d failed handshakes",
                after - before, attempts - 5))
    end)

    it("runs pre_tls before the handshake, so a refusal costs nothing", function()
        local reactor = Reactor.new()
        local server_cfg = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "test server"))
        local pre_called, handshaken = false, false

        assert(reactor:listen("127.0.0.1", 19308, function()
            handshaken = true
        end, {
            tls = server_cfg,
            pre_tls = function(_sock, _peer, ip)
                pre_called = ip
                return false
            end,
        }))

        reactor:spawn(function()
            local raw = assert(socket.connect("127.0.0.1", 19308))
            raw:settimeout(2)
            raw:receive(1)
            raw:close()
            reactor:sleep(0.1)
            reactor:stop()
        end)
        reactor:spawn(function() reactor:sleep(10); reactor:stop() end)
        reactor:run()
        reactor:shutdown()

        assert.are.equal("127.0.0.1", pre_called)
        assert.is_false(handshaken,
            "pre_tls must be able to refuse before any TLS work happens")
    end)
end)

describe("reactor want-state handling", function()

    it("parks on the direction TLS asks for, not the one the caller wanted", function()
        local reactor = Reactor.new()
        local sock = { name = "fake" }

        local co = coroutine.create(function()
            reactor:park(sock, "wantwrite", "read")
        end)
        coroutine.resume(co)
        assert.are.equal(co, reactor.write_waiters[sock])
        assert.is_nil(reactor.read_waiters[sock])

        local co2 = coroutine.create(function()
            reactor:park(sock, "wantread", "write")
        end)
        coroutine.resume(co2)
        assert.are.equal(co2, reactor.read_waiters[sock])
    end)

    it("falls back to the caller's direction for a plain timeout", function()
        local reactor = Reactor.new()
        local a, b = { name = "a" }, { name = "b" }

        local reader = coroutine.create(function() reactor:park(a, "timeout", "read") end)
        coroutine.resume(reader)
        assert.are.equal(reader, reactor.read_waiters[a])

        local writer = coroutine.create(function() reactor:park(b, "timeout", "write") end)
        coroutine.resume(writer)
        assert.are.equal(writer, reactor.write_waiters[b])
    end)

    it("reports a real error as not-would-block", function()
        assert.is_false(Reactor.would_block("closed"))
        assert.is_false(Reactor.would_block(nil))
        assert.is_true(Reactor.would_block("timeout"))
        assert.is_true(Reactor.would_block("wantread"))
        assert.is_true(Reactor.would_block("wantwrite"))

        local reactor = Reactor.new()
        local co = coroutine.create(function()
            assert.is_false(reactor:park({}, "closed", "read"))
        end)
        local ok = coroutine.resume(co)
        assert.is_true(ok)
    end)
end)

describe("tls channel binding", function()

    it("rejects anything that is not a PEM certificate", function()
        assert.is_nil((tls_m.der_from_pem("not a certificate")))
        assert.is_nil((tls_m.der_from_pem(nil)))
        assert.is_nil((tls_m.endpoint_hash_from_pem("-----BEGIN NOTHING-----")))
    end)

    it("derives a 32-byte endpoint hash that is unique per certificate", function()
        if not have_certs then return end
        local cfg = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY }, "Server.Tls"))
        assert.are.equal("preferred", cfg.channel_binding)
        assert.are.equal(32, #cfg.endpoint_hash)

        local other = assert(tls_m.server_config(
            { CertFile = OTHER_CERT, KeyFile = OTHER_KEY }, "Server.Tls"))
        assert.are_not.equal(cfg.endpoint_hash, other.endpoint_hash)
    end)

    it("leaves the hash out when channel binding is switched off", function()
        if not have_certs then return end
        local cfg = assert(tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY, ChannelBinding = "disabled" },
            "Server.Tls"))
        assert.is_nil(cfg.endpoint_hash)
    end)

    it("refuses an unknown ChannelBinding mode", function()
        if not have_certs then return end
        local cfg, err = tls_m.server_config(
            { CertFile = CERT, KeyFile = KEY, ChannelBinding = "maybe" }, "Server.Tls")
        assert.is_nil(cfg)
        assert.is_truthy(err:find("ChannelBinding"))
    end)

end)
