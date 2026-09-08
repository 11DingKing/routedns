# Lua Scripting

[Guide index](configuration.md) | [Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | [Modifiers](modifiers.md) | [Responders](responders.md) | **Lua Scripting** | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | [Resolvers](resolvers.md) | [Templates](templates.md)

## Lua

`type = "lua"`

Lua groups allow writing custom query handling logic using Lua scripts. The script must define a `Resolve(msg, ci)` function that receives the DNS message and client info, and returns a response message and error. Scripts run in a sandboxed environment by default with access to DNS types, message construction, and upstream resolvers.

### Configuration

To enable a Lua group, add an element with `type = "lua"` in the groups section of the configuration. Either `lua-script` or `lua-script-source` must be provided.

Options:

- `resolvers` - Array of upstream resolvers accessible in the script as `Resolvers[1]`, `Resolvers[2]`, etc.
- `lua-script` - Inline Lua script (multi-line string in TOML using `"""`).
- `lua-script-source` - Path to an external `.lua` file. Alternative to `lua-script`.
- `lua-concurrency` - Number of concurrent Lua VM instances (pool size). Default `4`.
- `lua-no-sandbox` - Disable the sandbox to allow `io`, `os`, `debug`, and dynamic code loading. Default `false`.
- `lua-script-watch` - Watch the external script file (`lua-script-source`) and hot-reload it when it changes. Requires `lua-script-source`; inline scripts are never watched. Default `false`, in which case the script is loaded once at startup and changing it requires a restart.
- `lua-script-watch-poll` - How often the script file is checked for changes, e.g. `"500ms"` or `"2s"`. Default `1s`.

### Sandbox

By default, scripts run in a sandbox that provides access to safe libraries: `base` (with dangerous functions removed), `string`, `math`, `table`, and `coroutine`. The following functions are blocked in sandbox mode: `dofile`, `loadfile`, `load`, `loadstring`, `module`, `require`. The `io`, `os`, `debug`, and `package` libraries are not loaded.

Set `lua-no-sandbox = true` to disable the sandbox and allow full access to all Lua libraries. Only use this for trusted scripts.

### Hot-reloading external scripts

Set `lua-script-watch = true` with `lua-script-source` to have the group pick up script changes without a restart:

```toml
[groups.lua-custom]
type = "lua"
resolvers = ["cloudflare-dot"]
lua-script-source = "/etc/routedns/custom.lua"
lua-script-watch = true
lua-script-watch-poll = "1s"
```

The file is polled for changes. When it changes, a complete new generation of Lua VMs is built: the file is read in full, compiled, and each VM runs through the same initialization as at startup (sandbox, constants, DNS types, `ClientInfo`, and upstream resolver injection). The new generation is published atomically only after the entire VM pool is ready. Requests that borrowed a VM from the previous generation finish on it and then release it; every new request is served by the current generation. Superseded VMs are closed once the request using them completes, so no request ever runs against a half-loaded or closed state.

If the file is deleted or unreadable, fails to compile, lacks a `Resolve` function, or fails to initialize, the previous complete generation keeps serving traffic. The failure is logged and recorded (observable as the group's reload error); the watcher keeps retrying and switches automatically once the file is valid again. Rewriting the file with the same content as the loaded generation is a no-op. Watching is disabled by default and does not apply to inline `lua-script` configurations, which keep their load-once behavior.

### Lua API

Scripts have access to the following types and globals:

- **Message** - DNS message. Create with `Message.new()`. Fields: `id`, `response`, `rcode`, `authoritative`, `recursion_desired`, `recursion_available`, `authenticated_data`, `questions`, `answer`, `ns`, `extra`. Methods: `:set_reply(request)`, `:set_question(name, type)`, `:is_edns0()`, `:set_edns0(udpsize, do)`. Note: methods use Lua colon syntax (e.g. `msg:set_reply(request)`).
- **Question** - DNS question. Create with `Question.new(name, qtype, qclass)`. Fields: `name`, `qtype`, `qclass`.
- **RR** - Resource record. Create with `RR.new({rtype = TypeA, name = "example.com.", class = ClassIN, ttl = 300, a = "1.2.3.4"})`. Header fields: `name`, `rtype`, `class`, `ttl`, `rdlength`. Data fields are type-specific and use lowercase names (e.g., `a`, `aaaa`, `ns`, `cname`, `mx`, `preference`, `target`, etc.).
- **OPT** - EDNS0 OPT pseudo-record. Create with `OPT.new(udp_size, do_bit)`. Fields: `udp_size`, `do_bit`, `version`, `extended_rcode`, `option` (array of EDNS0 options), `name`, `rtype`. Also returned by `Message:is_edns0()` and created implicitly by `Message:set_edns0(udp_size, do_bit)`.
- **ClientInfo** - Client information passed as the second argument (`ci`) to `Resolve(msg, ci)`. Read-only fields: `source_ip` (string or nil), `doh_path` (string), `tls_server_name` (string), `listener` (string), `protocol` (string, the transport the query arrived on, one of `udp`, `tcp`, `dot`, `doh`, `doq`, `dtls` or `odoh`), `listener_addr` (string, the address the receiving listener is bound to). The last two are empty for queries that were not produced by a listener, such as those from the `prefetch` component.
- **Error** - Error value. Create with `Error.new("message")`. Methods: `error()`.
- **Resolvers** - Table of upstream resolvers. Each resolver has a `:resolve(msg, ci)` method that returns `(response, error)` (e.g. `Resolvers[1]:resolve(msg, ci)`).
- **DNS constants** - Type constants (`TypeA`, `TypeAAAA`, `TypeMX`, ...), class constants (`ClassIN`, `ClassCH`, ...), rcode constants (`RcodeNOERROR`, `RcodeNXDOMAIN`, ...).
- **BuildVersion** - String constant containing the RouteDNS build version (e.g. `"v0.1.138"`).
- **EDNS0 option constants** - `EDNS0SUBNET`, `EDNS0COOKIE`, `EDNS0EDE`, `EDNS0PADDING`, etc.
- **EDNS0 types** - `EDNS0_SUBNET`, `EDNS0_COOKIE`, `EDNS0_EDE`, `EDNS0_PADDING`, `EDNS0_NSID`, `EDNS0_LOCAL`, and others. Each has a `new(...)` constructor and field accessors.

### Examples

Simple passthrough to an upstream resolver:

```toml
[groups.lua-proxy]
type = "lua"
resolvers = ["cloudflare-dot"]
lua-script = """
function Resolve(msg, ci)
    local answer, err = Resolvers[1]:resolve(msg, ci)
    if err ~= nil then
        return nil, err
    end
    return answer, nil
end
"""
```

Return a static A record for a specific domain, forwarding everything else upstream:

```toml
[groups.lua-static]
type = "lua"
resolvers = ["cloudflare-dot"]
lua-script = """
function Resolve(msg, ci)
    local q = msg.questions[1]

    -- Return a static A record for "example.com"
    if q.name == "example.com." and q.qtype == TypeA then
        local answer = Message.new()
        answer:set_reply(msg)
        local rr = RR.new({rtype = TypeA, name = q.name, class = ClassIN, ttl = 300, a = "192.168.1.1"})
        answer.answer = { rr }
        return answer, nil
    end

    -- Forward everything else upstream
    return Resolvers[1]:resolve(msg, ci)
end
"""
```

Route queries to different resolvers based on name patterns:

```toml
[groups.lua-router]
type = "lua"
resolvers = ["cloudflare-dot", "google-dot"]
lua-script = """
function Resolve(msg, ci)
    local q = msg.questions[1]
    local name = q.name

    -- Route .google.com queries to Google DNS
    if string.find(name, "google%.com%.$") then
        return Resolvers[2]:resolve(msg, ci)
    end

    -- Everything else goes to Cloudflare
    return Resolvers[1]:resolve(msg, ci)
end
"""
```

Route queries based on client information (source IP, listener, TLS server name):

```toml
[groups.lua-client-routing]
type = "lua"
resolvers = ["internal-resolver", "external-resolver"]
lua-script = """
function Resolve(msg, ci)
    -- Route queries from internal network to internal resolver
    if ci.source_ip ~= nil and string.find(ci.source_ip, "^192%.168%.") then
        return Resolvers[1]:resolve(msg, ci)
    end

    -- Route based on TLS server name
    if ci.tls_server_name == "private.dns.example.com" then
        return Resolvers[1]:resolve(msg, ci)
    end

    -- Treat anything that arrived over an encrypted transport as trusted
    if ci.protocol == "dot" or ci.protocol == "doh" or ci.protocol == "doq" then
        return Resolvers[1]:resolve(msg, ci)
    end

    -- Everything else goes to the external resolver
    return Resolvers[2]:resolve(msg, ci)
end
"""
```

Load the script from an external file:

```toml
[groups.lua-custom]
type = "lua"
resolvers = ["cloudflare-dot"]
lua-script-source = "/etc/routedns/custom.lua"
```

Block a domain with NXDOMAIN and attach an EDNS0 Extended DNS Error (EDE):

```toml
[groups.lua-ede-block]
type = "lua"
lua-script = """
function Resolve(msg, ci)
    local q = msg.questions[1]

    if q.name == "blocked.example.com." then
        local answer = Message.new()
        answer:set_reply(msg)
        answer.rcode = RcodeNXDOMAIN

        -- Add EDNS0 OPT with an EDE option (info code 15 = Blocked)
        answer:set_edns0(4096, false)
        local opt = answer:is_edns0()
        local ede = EDNS0_EDE.new(15, "domain blocked by policy")
        opt.option = { ede }

        return answer, nil
    end

    return Resolvers[1]:resolve(msg, ci)
end
"""
resolvers = ["cloudflare-dot"]
```

Example config files: [lua-passthrough.toml](../cmd/routedns/example-config/lua-passthrough.toml), [lua-static-answer.toml](../cmd/routedns/example-config/lua-static-answer.toml), [lua-routing.toml](../cmd/routedns/example-config/lua-routing.toml), [lua-opt.toml](../cmd/routedns/example-config/lua-opt.toml)
