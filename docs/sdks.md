# SDKs

Four client SDKs — Go, Python, Node.js, and Java — let an application fetch
secrets directly at startup instead of hardcoding them. All four live together
in [keyorixhq/keyorix-sdks](https://github.com/keyorixhq/keyorix-sdks)
(Apache-2.0, independent of this server's own AGPL-3.0 license — see that
repo's ADR-072 for why). `github.com/keyorixhq/keyorix-go` is **archived**:
it predates this consolidation and is superseded entirely by the `go/`
directory in `keyorix-sdks` — don't `go get` it for new code.

No `keyorix-sdks` release has been tagged yet. Each SDK's manifest currently
declares `0.3.0`; see that repo's `COMPATIBILITY.md` for the exact server
commit each version was last verified against, and each SDK's own
`CHANGELOG.md` for what changed.

## Authentication

All three token types the server issues present identically over the wire
(`Authorization: Bearer <token>`, dispatched by prefix) — every SDK's client
constructor accepts any of them with no code difference:

- **Machine identity token** (recommended for an app running unattended).
  Issue one via `keyorix machine token issue <name|id>` or the web UI
  (Project → Machine Identities → Issue Token), then load it from your
  app's own secret store or environment — never hardcode it.
- **Personal access token (PAT)** — `keyorix pat create`. Scoped to the
  creating user's own permissions.
- **Session token** — obtained via each SDK's `login`/`Login` function
  (username + password). Intended for interactive use (a developer at a
  terminal, the CLI's own login flow), not for an application's
  long-running credential.

```go
// Go
client, err := keyorix.New("https://your-server:8443", os.Getenv("KEYORIX_TOKEN"))
```
```python
# Python
client = keyorix.Client("https://your-server:8443", os.environ["KEYORIX_TOKEN"])
```
```javascript
// Node.js
const client = new keyorix.Client("https://your-server:8443", process.env.KEYORIX_TOKEN);
```
```java
// Java
KeyorixClient client = Keyorix.newClient("https://your-server:8443", System.getenv("KEYORIX_TOKEN"));
```

MFA is not currently handled by any of the four SDKs: if the authenticating
account has TOTP/passkey enrolled, `login`/`Login` will fail rather than
prompt for a second factor. Use a machine identity token or a PAT for
automated/unattended access instead (neither triggers an MFA check).

## Fetching a secret

Scoped to a project + environment — an environment name is only unique
within one project, not globally, so every SDK requires both:

```go
dbPassword, err := client.GetSecretScoped(ctx, "db-password",
    keyorix.ProjectByName("my-project"), keyorix.EnvironmentByName("production"))
```
```python
db_password = client.get_secret_scoped("db-password", "my-project", "production")
```
```javascript
const dbPassword = await client.getSecretScoped("db-password", "my-project", "production");
```
```java
String dbPassword = client.getSecretScoped("db-password", "my-project", "production");
```

`project`/`environment` each accept either a name (resolved to an ID via the
server and cached on the client for its lifetime) or a numeric ID (no
resolution round trip). A name match that's ambiguous or missing raises a
typed error/exception (`SecretNotFoundError`/`AmbiguousSecretError` and
per-language equivalents) rather than guessing.

The older environment-only `GetSecret`/`getSecret` methods (no project
argument) were removed in each SDK's `v0.3.0` — an environment name alone
could silently resolve to a different project's same-named secret. If you
find sample code using them, it predates this change; use the scoped method
shown above instead.

## Error handling

Every request path returns/throws a typed error for the three statuses an
application most commonly needs to branch on, instead of one generic error
for everything:

| HTTP status | Go | Node | Python | Java |
|---|---|---|---|---|
| 401 | `*AuthError` | `AuthError` | `AuthError` | `AuthException` |
| 403 | `*ForbiddenError` | `ForbiddenError` | `ForbiddenError` | `ForbiddenException` |
| 404 | `*NotFoundError` | `NotFoundError` | `NotFoundError` | `NotFoundException` |
| anything else | `*APIError` | `KeyorixError` | `KeyorixError` | `KeyorixException` |

Every error/exception's default message omits the raw server response body
(it's server-controlled content some sample code passes straight to a log
call); the raw body remains available to callers who explicitly opt in
(`.Body`/`.responseBody`/`.response_body`/`.getResponseBody()`).

## TLS with a private CA

For a server whose certificate isn't signed by a CA in your OS/JVM's default
trust store:

- **Go**: pass a custom `*http.Client` via `keyorix.WithHTTPClient(...)`,
  built with your own `tls.Config`/`x509.CertPool`.
- **Node.js**: `new keyorix.Client(url, token, { ca: caCertPem })`.
- **Python**: `keyorix.Client(url, token, ca_file="/path/to/ca.pem")`.
- **Java**: `new KeyorixClient(url, token, timeout, "/path/to/ca.pem")`.

TLS certificate verification is never silently disabled by any of the four —
each has a test that spins up a real TLS server with a throwaway self-signed
cert and confirms the connection is rejected by default, then succeeds only
once the matching CA is supplied.

## Timeouts

All four default to a 30-second request timeout, configurable per client
(`keyorix.WithTimeout(d)` in Go; a `timeout`/`ca_file` constructor
option/parameter in Node/Python; a `Duration` constructor argument in Java).

## Full API reference

Each SDK's own README in
[keyorix-sdks](https://github.com/keyorixhq/keyorix-sdks) documents its
exact method signatures, and `COMPATIBILITY.md` there tracks per-endpoint
coverage against this server's API — verified by that repo's own CI against
a real, freshly-built `keyorix-server`, not asserted by hand.
