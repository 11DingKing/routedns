# Logging

[Guide index](configuration.md) | [Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | [Modifiers](modifiers.md) | [Responders](responders.md) | [Lua Scripting](scripting.md) | [DNSSEC and Rate Limiting](security.md) | **Logging** | [Resolvers](resolvers.md) | [Templates](templates.md)

## Syslog

`type = "syslog"`

The `syslog` element can be used to log requests and/or responses to local or remote syslog servers. It forwards queries un-modified to the configured resolver. It is possible to configure multiple syslog loggers in different places. For example a logger could be configured to log and forward queries for domains on a blocklist, or behind a router.

### Configuration

To enable syslog, add an element with `type = "syslog"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `network` - Network protocol. `udp`, `tcp` or `unix`. Defaults to `unix`.
- `address` - Remote syslog server address and port. For example `192.168.0.1:514`
- `priority` - Syslog priority. Possible values: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, `debug`
- `tag` - Syslog tag. Defaults to the program name.
- `log-request` - Enable logging of requests. Default `false`.
- `log-response` - Enable logging of responses. Default `false`.
- `verbose` - Log all answers, not just the types that match the query. Default `false`.

### Examples

```toml
[groups.cloudflare-logged]
type = "syslog"
resolvers = ["cloudflare-dot"]
network = "udp"
address = "192.168.0.1:514"
priority = "info"
tag = "routedns"
log-request = true
log-response = true
```

Example config files: [syslog.toml](../cmd/routedns/example-config/syslog.toml)

## Query Log

`type = "query-log"`

The `query-log` element logs all DNS query details, including time, client IP, DNS question name, class and type. Logs can be written to a file or STDOUT. When writing to a file, logs are appended and the file can optionally be rotated once it reaches a configured size.

### Configuration

To enable query-logging, add an element with `type = "query-log"` in the groups section of the configuration.

Options:

- `output-file` - Name of the file to write logs to, leave blank for STDOUT. Logs are appended to the file. When running under the systemd unit shipped with the packages, use a path under `/var/log/routedns`; see [Writable Paths](overview.md#writable-paths).
- `output-format` - Output format. Defaults to "text".
- `rotation-size` - Rotate the log file once it would grow past this size, for example `rotation-size = "100MB"`. A bare number is interpreted as bytes; units `k`, `m`, `g` and `t` (with optional `b` or `ib` suffix, e.g. `100MB` or `1GiB`) are binary (1K = 1024 bytes). Leave unset (or `0`) to disable rotation, in which case the file is appended to without limit. Requires `output-file`. On rotation the active file is renamed to `<output-file>.<n>` with a deterministic, monotonically increasing suffix (`query.log.1`, `query.log.2`, ...) that continues across restarts, existing archives are never overwritten, and a new active file is opened. Each log record is written whole into exactly one file. If archiving or reopening the file fails (for example a read-only directory), logging continues to the current file, the failure is logged and retried with the next record.

### Examples

```toml
[groups.query-log]
type   = "query-log"
resolvers = ["cloudflare-dot"]
output-file = "/var/log/routedns/query.log"
output-format = "text"
rotation-size = "100MB" # rotate once the file grows past 100MiB
```

Example config files: [query-log.toml](../cmd/routedns/example-config/query-log.toml)
