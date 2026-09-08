local scram    = require("src.server.scram")
local auth     = require("src.server.auth")
local users_m  = require("src.server.users")
local handlers = require("src.server.handlers")
local proto    = require("src.wire.protocol")
local uuid     = require("src.core.uuid")
local pbkdf2   = require("src.core.pbkdf2")
local b64      = require("src.core.base64")
local rng      = require("src.core.rng")

describe("base64", function()

    it("matches the RFC 4648 test vectors", function()
        local vectors = {
            { "",       ""         },
            { "f",      "Zg=="     },
            { "fo",     "Zm8="     },
            { "foo",    "Zm9v"     },
            { "foob",   "Zm9vYg==" },
            { "fooba",  "Zm9vYmE=" },
            { "foobar", "Zm9vYmFy" },
        }
        for _, v in ipairs(vectors) do
            assert.are.equal(v[2], b64.encode(v[1]))
            assert.are.equal(v[1], (b64.decode(v[2])))
        end
    end)

    it("round-trips arbitrary bytes", function()
        for len = 1, 40 do
            local raw = rng.bytes(len)
            assert.are.equal(raw, (b64.decode(b64.encode(raw))))
        end
    end)

    it("rejects malformed input rather than guessing at it", function()
        assert.is_nil((b64.decode("Zm9vYmF")))
        assert.is_nil((b64.decode("Zm9vYmF!")))
        assert.is_nil((b64.decode("Zm=vYmFy")))
        assert.is_nil((b64.decode("Zh==")))
        assert.is_nil((b64.decode("Zm9v YmFy")))
    end)
end)

describe("SCRAM-SHA-256 against the RFC 7677 vector", function()

    local PASSWORD     = "pencil"
    local CLIENT_NONCE = "rOprNGfwEbeRWgbNEkqO"
    local COMBINED     = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
    local SALT_B64     = "W22ZaJ0SNY7soEsUEjb6gQ=="
    local ITERATIONS   = 4096

    local CLIENT_FIRST = "n,,n=user,r=" .. CLIENT_NONCE
    local SERVER_FIRST = "r=" .. COMBINED .. ",s=" .. SALT_B64 .. ",i=" .. ITERATIONS
    local CLIENT_FINAL = "c=biws,r=" .. COMBINED
        .. ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
    local SERVER_FINAL = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

    local salt = assert(b64.decode(SALT_B64))

    it("produces the published client-final message", function()
        local salted = pbkdf2.pbkdf2_hmac_sha256(PASSWORD, salt, ITERATIONS, 32)
        local _, bare = scram.client_first("user", CLIENT_NONCE)
        assert.are.equal("n=user,r=" .. CLIENT_NONCE, bare)

        local final = scram.client_final(salted, bare, SERVER_FIRST, COMBINED)
        assert.are.equal(CLIENT_FINAL, final)
    end)

    it("accepts the published proof server-side and answers with the published signature", function()
        local salted = pbkdf2.pbkdf2_hmac_sha256(PASSWORD, salt, ITERATIONS, 32)
        local stored_key, server_key = scram.keys_from_salted(salted)

        local first = assert(scram.parse_client_first(CLIENT_FIRST))
        assert.are.equal("user", first.username)
        assert.are.equal(CLIENT_NONCE, first.nonce)

        local final = assert(scram.parse_client_final(CLIENT_FINAL))
        assert.is_true(scram.check_cbind(first.gs2, final.cbind))

        local auth_message = scram.auth_message(first.bare, SERVER_FIRST, final.without_proof)
        assert.is_true(scram.verify_proof(stored_key, auth_message, final.proof))
        assert.are.equal(SERVER_FINAL, scram.server_final(server_key, auth_message))
    end)

    it("lets the client verify the published server signature", function()
        local salted = pbkdf2.pbkdf2_hmac_sha256(PASSWORD, salt, ITERATIONS, 32)
        local _, bare = scram.client_first("user", CLIENT_NONCE)
        local _, expected = scram.client_final(salted, bare, SERVER_FIRST, COMBINED)
        assert.is_true(scram.verify_server_final(SERVER_FINAL, expected))
        assert.is_false((scram.verify_server_final(
            "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", expected)))
    end)
end)

describe("SCRAM message parsing", function()

    it("parses a client-first that demands channel binding", function()
        local first = assert(scram.parse_client_first("p=tls-unique,,n=user,r=abc"))
        assert.are.equal("p", first.cbind_flag)
        assert.are.equal("tls-unique", first.cbind_name)
        assert.are.equal("p=tls-unique,,", first.gs2)
    end)

    it("rejects a channel-binding flag with no type", function()
        local ok, err = scram.parse_client_first("p,,n=user,r=abc")
        assert.is_nil(ok)
        assert.is_truthy(err:find("channel%-binding flag"))
    end)

    it("rejects an authzid rather than silently ignoring it", function()
        local ok, err = scram.parse_client_first("n,a=admin,n=user,r=abc")
        assert.is_nil(ok)
        assert.is_truthy(err:find("authzid"))
    end)

    it("requires the username and nonce fields", function()
        assert.is_nil((scram.parse_client_first("n,,r=abc")))
        assert.is_nil((scram.parse_client_first("n,,n=user")))
        assert.is_nil((scram.parse_client_first("n,,n=user,r=")))
        assert.is_nil((scram.parse_client_first("")))
    end)

    it("round-trips escaped usernames", function()
        for _, name in ipairs({ "a=b", "a,b", "plain", "=2C", "a=b,c=d" }) do
            local escaped = scram.escape_username(name)
            assert.is_nil(escaped:find(","), "comma must be escaped")
            assert.are.equal(name, (scram.unescape_username(escaped)))
        end
    end)

    it("rejects an invalid escape instead of passing it through", function()
        assert.is_nil((scram.unescape_username("a=ZZb")))
        assert.is_nil((scram.unescape_username("ab=")))
    end)

    it("takes the first value of a duplicated field", function()
        local first = assert(scram.parse_client_first("n,,n=user,r=aaa,r=bbb"))
        assert.are.equal("aaa", first.nonce)
    end)

    it("requires the server nonce to extend the client nonce", function()
        local ok, err = scram.parse_server_first("r=totallydifferent,s=YWJj,i=4096", "mynonce")
        assert.is_nil(ok)
        assert.is_truthy(err:find("extend"))

        assert.is_nil((scram.parse_server_first("r=mynonce,s=YWJj,i=4096", "mynonce")))
        assert.is_truthy(scram.parse_server_first("r=mynonceXYZ,s=YWJj,i=4096", "mynonce"))
    end)

    it("rejects a nonsensical iteration count", function()
        assert.is_nil((scram.parse_server_first("r=abcX,s=YWJj,i=0", "abc")))
        assert.is_nil((scram.parse_server_first("r=abcX,s=YWJj,i=x", "abc")))
    end)

    it("surfaces a server error field", function()
        local ok, err = scram.parse_server_first("e=unknown-user", "abc")
        assert.is_nil(ok)
        assert.is_truthy(err:find("unknown%-user"))
    end)
end)

describe("SCRAM exchange", function()

    local ITER = 2048

    local function exchange(credential, password, opts)
        opts = opts or {}
        local parsed = assert(auth.parse_credential(credential))
        local stored_key, server_key = auth.scram_keys(parsed)

        local client_nonce = scram.nonce(rng.bytes)
        local client_first, bare = scram.client_first("alice", client_nonce)

        local first = assert(scram.parse_client_first(client_first))
        local combined = first.nonce .. scram.nonce(rng.bytes)
        local server_first = scram.server_first(combined, parsed.salt, parsed.iterations)

        local sf = assert(scram.parse_server_first(server_first, client_nonce))
        local salted = pbkdf2.pbkdf2_hmac_sha256(password, sf.salt, sf.iterations, 32)
        local client_final, expected =
            scram.client_final(salted, bare, server_first, sf.nonce)

        local final = assert(scram.parse_client_final(client_final))
        assert.are.equal(combined, final.nonce, "client must echo the issued nonce")
        if opts.tamper_proof then
            final.proof = string.char(final.proof:byte(1) ~ 0xFF) .. final.proof:sub(2)
        end

        local auth_message = scram.auth_message(first.bare, server_first, final.without_proof)
        local ok = scram.verify_proof(stored_key, auth_message, final.proof)
        return ok, {
            server_final = scram.server_final(server_key, auth_message),
            expected     = expected,
        }
    end

    it("succeeds against a pbkdf2-format credential", function()
        local cred = auth.hash_password("s3cret", { iterations = ITER })
        local ok, out = exchange(cred, "s3cret")
        assert.is_true(ok)
        assert.is_true(scram.verify_server_final(out.server_final, out.expected))
    end)

    it("succeeds against a scram-format credential", function()
        local cred = auth.hash_password("s3cret",
            { iterations = ITER, format = auth.FORMAT_SCRAM })
        local ok, out = exchange(cred, "s3cret")
        assert.is_true(ok)
        assert.is_true(scram.verify_server_final(out.server_final, out.expected))
    end)

    it("produces identical keys from both stored formats of one password", function()
        local pb = auth.hash_password("s3cret", { iterations = ITER })
        local parsed = assert(auth.parse_credential(pb))
        local sk1, vk1 = auth.scram_keys(parsed)

        local sk2, vk2 = scram.keys_from_salted(parsed.hash)
        assert.are.equal(sk1, sk2)
        assert.are.equal(vk1, vk2)
    end)

    it("rejects a wrong password", function()
        local cred = auth.hash_password("s3cret", { iterations = ITER })
        assert.is_false((exchange(cred, "not-s3cret")))
    end)

    it("rejects a tampered proof", function()
        local cred = auth.hash_password("s3cret", { iterations = ITER })
        assert.is_false((exchange(cred, "s3cret", { tamper_proof = true })))
    end)

    it("rejects a client-final replayed against a fresh challenge", function()
        local cred = auth.hash_password("s3cret", { iterations = ITER })
        local parsed = assert(auth.parse_credential(cred))
        local stored_key = auth.scram_keys(parsed)

        local client_nonce = scram.nonce(rng.bytes)
        local client_first, bare = scram.client_first("alice", client_nonce)
        local first = assert(scram.parse_client_first(client_first))

        local server_first_1 = scram.server_first(
            first.nonce .. scram.nonce(rng.bytes), parsed.salt, parsed.iterations)
        local sf1 = assert(scram.parse_server_first(server_first_1, client_nonce))
        local salted = pbkdf2.pbkdf2_hmac_sha256("s3cret", sf1.salt, sf1.iterations, 32)
        local captured = scram.client_final(salted, bare, server_first_1, sf1.nonce)
        local final = assert(scram.parse_client_final(captured))

        assert.is_true(scram.verify_proof(stored_key,
            scram.auth_message(first.bare, server_first_1, final.without_proof),
            final.proof))

        local server_first_2 = scram.server_first(
            first.nonce .. scram.nonce(rng.bytes), parsed.salt, parsed.iterations)
        assert.are_not.equal(server_first_1, server_first_2)
        assert.is_false(scram.verify_proof(stored_key,
            scram.auth_message(first.bare, server_first_2, final.without_proof),
            final.proof))
    end)

    it("detects a stripped gs2 header via the c= field", function()
        local first = assert(scram.parse_client_first("n,,n=alice,r=abc"))
        assert.is_true(scram.check_cbind(first.gs2, "biws"))
        assert.is_false((scram.check_cbind(first.gs2, "eSws")))
        assert.is_false((scram.check_cbind(first.gs2, nil)))
    end)
end)

describe("SCRAM channel binding", function()

    local BIND  = string.rep(string.char(7), 32)
    local OTHER = string.rep(string.char(9), 32)

    local function client_first_with(flag)
        return assert(scram.parse_client_first(flag .. "n=alice,r=abc"))
    end

    it("binds a p= exchange to the endpoint hash the server offers", function()
        local first = client_first_with("p=tls-server-end-point,,")
        assert.are.equal(BIND, scram.negotiate_cbind(first, BIND, "preferred"))
    end)

    it("refuses a channel-binding type it does not implement", function()
        local first = client_first_with("p=tls-unique,,")
        local bound, err = scram.negotiate_cbind(first, BIND, "preferred")
        assert.is_nil(bound)
        assert.is_truthy(err:find("unsupported channel%-binding type"))
    end)

    it("refuses p= on a connection with nothing to bind to", function()
        local first = client_first_with("p=tls-server-end-point,,")
        local bound, err = scram.negotiate_cbind(first, nil, "preferred")
        assert.is_nil(bound)
        assert.is_truthy(err:find("not available"))
    end)

    it("treats y= as a downgrade when the server can bind", function()
        local first = client_first_with("y,,")
        local bound, err = scram.negotiate_cbind(first, BIND, "preferred")
        assert.is_nil(bound)
        assert.is_truthy(err:find("downgrade"))

        assert.are.equal("", scram.negotiate_cbind(first, nil, "preferred"))
    end)

    it("lets an unbound client through unless the listener requires binding", function()
        local first = client_first_with("n,,")
        assert.are.equal("", scram.negotiate_cbind(first, BIND, "preferred"))

        local bound, err = scram.negotiate_cbind(first, BIND, "required")
        assert.is_nil(bound)
        assert.is_truthy(err:find("requires"))
    end)

    it("round-trips a bound exchange and rejects a swapped certificate", function()
        local salted = pbkdf2.pbkdf2_hmac_sha256("pencil", "salt-salt-salt-sa", 1, 32)
        local client_first, bare, gs2 =
            scram.client_first("alice", "cnonce", scram.CBIND_TYPE)
        local first = assert(scram.parse_client_first(client_first))
        local bound = assert(scram.negotiate_cbind(first, BIND, "preferred"))

        local server_first = scram.server_first("cnonce-server", "salt-salt-salt-sa", 1)
        local message = scram.client_final(salted, bare, server_first,
            "cnonce-server", gs2 .. BIND)
        local final = assert(scram.parse_client_final(message))

        assert.is_true(scram.check_cbind(first.gs2, final.cbind, bound))
        assert.is_false((scram.check_cbind(first.gs2, final.cbind, OTHER)))
        assert.is_false((scram.check_cbind(first.gs2, final.cbind, nil)))

        local stored_key = scram.keys_from_salted(salted)
        local auth_message = scram.auth_message(first.bare, server_first,
            final.without_proof)
        assert.is_true(scram.verify_proof(stored_key, auth_message, final.proof))
    end)
end)

describe("SCRAM over the wire, through the handlers", function()


    local ITER = 1000
    local PASSWORD = "orders-pw"

    local server

    local function fake_conn()
        return {
            id_short = "test",
            ip       = "10.0.0.1",
            state    = "greeted",
            sent     = {},
            closed   = nil,
            send = function(self, frame)
                self.sent[#self.sent + 1] = frame
                return true
            end,
            close = function(self, reason, code, message)
                self.closed = { reason = reason, code = code, message = message }
                self.state = "closed"
            end,
            transition_to = function(self, state) self.state = state end,
        }
    end

    local function unframe(frame) return proto.parse_frame(frame:sub(5)) end

    local function last(conn)
        local op, _, payload = unframe(conn.sent[#conn.sent])
        return op, payload
    end

    before_each(function()
        local store = assert(users_m.load({
            Users = {
                { Username = "orders",
                  PasswordHash = auth.hash_password(PASSWORD,
                      { iterations = ITER, format = auth.FORMAT_SCRAM }),
                  Acls = { { Resource = "topic", Name = "orders.*",
                             Operations = { "read", "write" } } } },
            },
        }))
        server = { authenticator = auth.authenticator({ store = store }) }
    end)

    local function handshake(username, password, tamper)
        local conn = fake_conn()
        local client_nonce = scram.nonce(rng.bytes)
        local client_first, bare = scram.client_first(username, client_nonce)

        local _, _, p1 = unframe(proto.encode_auth_scram(
            uuid.bytes(), scram.MECHANISM, client_first))
        handlers.auth_scram(server, conn, uuid.bytes(), p1)
        if conn.closed then return conn end

        local op, payload = last(conn)
        assert.are.equal(proto.OP_AUTH_CHALLENGE, op)
        local challenge = assert(proto.decode_auth_challenge(payload))
        local sf = assert(scram.parse_server_first(challenge.message, client_nonce))

        local salted = pbkdf2.pbkdf2_hmac_sha256(password, sf.salt, sf.iterations, 32)
        local client_final, expected =
            scram.client_final(salted, bare, challenge.message, sf.nonce)
        if tamper then client_final = tamper(client_final, sf) end

        local _, _, p2 = unframe(proto.encode_auth_scram_final(uuid.bytes(), client_final))
        handlers.auth_scram_final(server, conn, uuid.bytes(), p2)
        conn.expected_signature = expected
        return conn
    end

    it("authenticates and attaches the principal", function()
        local conn = handshake("orders", PASSWORD)
        assert.is_nil(conn.closed)
        assert.are.equal("authenticated", conn.state)
        assert.are.equal("orders", conn.username)
        assert.are.equal("orders", conn.principal.username)
        assert.is_true(conn.principal.acl:authorized("topic", "orders.eu", "write"))
    end)

    it("returns a server signature the client can verify", function()
        local conn = handshake("orders", PASSWORD)
        local op, payload = last(conn)
        assert.are.equal(proto.OP_AUTH_OK, op)
        local final = assert(proto.decode_auth_ok(payload))
        assert.is_true(scram.verify_server_final(final.message, conn.expected_signature))
    end)

    it("clears the exchange state so a proof cannot be retried", function()
        local conn = handshake("orders", PASSWORD)
        assert.is_nil(conn.scram)
    end)

    it("closes the connection on a wrong password", function()
        local conn = handshake("orders", "wrong")
        assert.is_truthy(conn.closed)
        assert.are.equal(proto.ERR_AUTH_FAILED, conn.closed.code)
        assert.is_nil(conn.principal)
    end)

    it("closes on an unknown user, with the same error and after a challenge", function()
        local conn = handshake("ghost", PASSWORD)
        assert.is_truthy(conn.closed)
        assert.are.equal(proto.ERR_AUTH_FAILED, conn.closed.code)
        assert.are.equal("invalid credentials", conn.closed.message)
        assert.is_true(#conn.sent >= 1, "an unknown user still gets a challenge")
    end)

    it("rejects a final message that echoes a different nonce", function()
        local conn = handshake("orders", PASSWORD, function(client_final)
            return (client_final:gsub("r=[^,]+", "r=not-the-issued-nonce", 1))
        end)
        assert.is_truthy(conn.closed)
        assert.is_truthy(conn.closed.message:find("nonce"))
    end)

    it("rejects a final message with a rewritten channel binding", function()
        local conn = handshake("orders", PASSWORD, function(client_final)
            return (client_final:gsub("^c=biws", "c=eSws", 1))
        end)
        assert.is_truthy(conn.closed)
        assert.is_truthy(conn.closed.message:find("channel%-binding"))
    end)

    it("refuses a final message with no preceding client-first", function()
        local conn = fake_conn()
        local _, _, payload = unframe(proto.encode_auth_scram_final(
            uuid.bytes(), "c=biws,r=x,p=YWJj"))
        handlers.auth_scram_final(server, conn, uuid.bytes(), payload)
        assert.is_truthy(conn.closed)
        assert.are.equal(proto.ERR_BAD_PROTOCOL, conn.closed.code)
    end)

    it("refuses an unsupported mechanism", function()
        local conn = fake_conn()
        local _, _, payload = unframe(proto.encode_auth_scram(
            uuid.bytes(), "SCRAM-SHA-1", "n,,n=orders,r=abc"))
        handlers.auth_scram(server, conn, uuid.bytes(), payload)
        assert.is_truthy(conn.closed)
        assert.is_truthy(conn.closed.message:find("SCRAM%-SHA%-256"))
    end)

    it("refuses a banned IP before doing any work", function()
        for _ = 1, 5 do server.authenticator:note_failure("10.0.0.1") end
        local conn = fake_conn()
        local _, _, payload = unframe(proto.encode_auth_scram(
            uuid.bytes(), scram.MECHANISM, "n,,n=orders,r=abc"))
        handlers.auth_scram(server, conn, uuid.bytes(), payload)
        assert.is_truthy(conn.closed)
        assert.is_truthy(conn.closed.message:find("banned"))
        assert.are.equal(0, #conn.sent)
    end)

    it("counts a failed proof toward the per-IP lockout", function()
        for _ = 1, 4 do handshake("orders", "wrong") end
        assert.is_false(server.authenticator:is_banned("10.0.0.1"))
        handshake("orders", "wrong")
        assert.is_true(server.authenticator:is_banned("10.0.0.1"))
    end)
end)

describe("client and broker halves against each other", function()


    local Client = require("src.client")

    local ITER = 1000

    local function fake_transport(server, conn)
        local inbox = ""
        return {
            send = function(_self, data)
                local pos = 1
                while pos <= #data do
                    local len = string.unpack(">I4", data, pos)
                    local body = data:sub(pos + 4, pos + 3 + len)
                    pos = pos + 4 + len
                    local op, correl, payload = proto.parse_frame(body)
                    local handler = handlers.BY_OP[op]
                    assert(handler, string.format("no handler for op 0x%02x", op))
                    handler(server, conn, correl, payload)
                end
                return #data
            end,
            receive = function(_self, n)
                if #inbox == 0 then return nil, "closed", "" end
                local take = inbox:sub(1, n)
                inbox = inbox:sub(#take + 1)
                return take
            end,
            close = function() end,
            settimeout = function() end,
            _deliver = function(frame) inbox = inbox .. frame end,
        }
    end

    local function run(username, password, credential)
        local store = assert(users_m.load({
            Users = { { Username = "orders", PasswordHash = credential,
                        Superuser = true } },
        }))
        local server = { authenticator = auth.authenticator({ store = store }) }

        local transport
        local conn = {
            id_short = "test", ip = "10.0.0.1", state = "greeted",
            send = function(_self, frame) transport._deliver(frame); return true end,
            close = function(self, reason, code, message)
                self.closed = { reason = reason, code = code, message = message }
                self.state = "closed"
            end,
            transition_to = function(self, state) self.state = state end,
        }
        transport = fake_transport(server, conn)

        local client = setmetatable({ sock = transport, closed = false, timeout = 1 },
            Client)
        local err = client:_auth_scram(username, password)
        return err, conn
    end

    it("completes a handshake against a pbkdf2-format credential", function()
        local err, conn = run("orders", "pw",
            auth.hash_password("pw", { iterations = ITER }))
        assert.is_nil(err)
        assert.are.equal("authenticated", conn.state)
        assert.are.equal("orders", conn.username)
    end)

    it("completes a handshake against a scram-format credential", function()
        local err, conn = run("orders", "pw",
            auth.hash_password("pw", { iterations = ITER, format = auth.FORMAT_SCRAM }))
        assert.is_nil(err)
        assert.are.equal("authenticated", conn.state)
    end)

    it("reports a wrong password as an error rather than authenticating", function()
        local err, conn = run("orders", "wrong",
            auth.hash_password("pw", { iterations = ITER }))
        assert.is_truthy(err)
        assert.are_not.equal("authenticated", conn.state)
    end)

    it("reports an unknown user the same way", function()
        local err, conn = run("ghost", "pw",
            auth.hash_password("pw", { iterations = ITER }))
        assert.is_truthy(err)
        assert.are_not.equal("authenticated", conn.state)
    end)
end)
