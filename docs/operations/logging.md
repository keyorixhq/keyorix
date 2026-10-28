# Server logs

Set `server.log.format: json` to get one JSON object per log line, ready for a log
collector. The default, `text`, is unchanged.

```yaml
server:
  log:
    format: json
```

Lines written before the format is applied (configuration load and validation failures)
are always plain text. Everything after that is JSON.

## Fields

Every line has:

| Field | Meaning |
|---|---|
| `ts` | UTC time, RFC 3339 with nanoseconds |
| `level` | `debug`, `info`, `warn` or `error` |
| `msg` | the message |

Lines about an HTTP request (the access log, panics, and core's audit-write failures) also have:

| Field | Meaning |
|---|---|
| `request_id` | the request's correlation id, minted by the server (see below) |
| `client_request_id` | the caller's own `X-Request-ID`, cleaned; only when one was sent |
| `principal_type` | `anonymous`, `user` or `machine_identity`: who the request authenticated as |
| `route` | the matched route pattern, e.g. `/api/v1/secrets/{id}`, or `unmatched`. Never the raw path |

The access log line (`"msg":"http request"`) adds `method`, `uri` (with setup/reset tokens and
secret-reference query strings already redacted), `remote_addr`, `status`, `bytes` and `duration_ms`.
5xx responses are `error`, everything else `info`.

Level for the many pre-existing plain log lines is taken from their prefix: `PANIC`, `FATAL`,
`ERROR` and `SECURITY` are `error`, `WARN`/`WARNING` are `warn`, `DEBUG` is `debug`, anything else `info`.

## Request ids

- The server mints every request's id (24 hex characters). A caller's `X-Request-ID` is not
  adopted: it is cleaned (printable ASCII only, at most 128 characters) and logged as
  `client_request_id` next to our `request_id`, so a reverse proxy's own id still finds the
  line.
- The server's id is returned in the response's `X-Request-ID` header, so "what was the id of
  the failing call" can be answered from the client side and grepped here.
- The id travels from the HTTP edge through the request context into core, so a core log line for
  that request (for example a failed audit write) carries it. Audit writes that continue after the
  request has finished keep the same id.
- gRPC calls get a server-minted id too (an interceptor right after panic recovery). It is
  returned in the `x-request-id` response header and stamped on the audit rows the call writes;
  a client's own `x-request-id` is only recorded as `client_request_id`, never as our id. The
  gRPC access-log lines do not print it yet.

### The id on the audit row

Every audit row an HTTP or gRPC request writes stores the server's id in `audit_events.request_id`
(NULL for scheduler jobs, startup events and rows written by a replica older than schema
epoch 6). Join an audit row with its log lines on it. A row owed while the audit log refused
writes (a plain secret suspend, a degraded break-glass activation) is written later by the
backfill with the id of the request that caused it (`pending_audit_events.request_id`, schema
epoch 9).

To go from a log line to its audit rows, filter by the id:

```
GET /api/v1/audit/logs?request_id=<id>&start_time=<RFC 3339>     # also /audit/search?request_id=
keyorix audit logs --request-id <id> --since <RFC 3339> --wide
```

`/audit/export` and `/audit/export.csv` carry `request_id` on every row (CSV: last column). The
gRPC `AuditService.GetAuditLogs` takes the same filter. The match is exact, rows without an id
never match, and the column has no index: add a time window on a large audit trail.

The column is **outside the tamper-evident hash chain** and is **advisory**: anyone with write
access to the database can change it, and audit verification will not notice. After joining on
`request_id`, confirm the match on the hash-covered fields (the log line's principal and route
against the audit row's actor, event type and time). The `request_id=` filter and the
`request_id` field in every audit API response and export inherit this: they find rows by an
advisory value, they do not prove who wrote them. The SIEM forwarder's copy of each event
(`request_id` in its payload) is the off-box record of the value at write time. Design:
`docs/specs/audit-request-id.md`.

## Secrets in logs

Two controls, in this order of importance:

1. **Call sites do not log secret values.** `TestJSONLogs_ShapeCorrelationAndNoSecrets` starts a
   real server in JSON mode, pushes canary passwords, a canary secret value, a session token, bad
   bearer tokens and a bad personal access token through bootstrap, login, secret creation and
   rejected requests, and fails if any canary appears anywhere in the output.
2. **A scrubber catches recognisable shapes** that slip through: Keyorix credentials
   (`kx_pat_…`, `kx_machine_…`, …), `Bearer`/`Basic` values, JWTs, PEM private keys,
   `password=`/`token=`/`secret=`-style pairs (numeric ids such as `secret=12` are kept) and
   `scheme://user:password@host`. It applies in JSON mode only; in `text` mode lines are written
   as before.

The scrubber cannot recognise an arbitrary secret value written as free text. That is what the
canary test is for.

## Log injection

In JSON mode a message that looks like a log record is just data: it is escaped into `msg`. Only
the server's own structured logger can write a field-bearing line, and it proves it with a
per-process random marker no log text can know.
