# Why did Keyorix refuse to start (or to run this command)?

Keyorix fails closed: when a setting, a key file, the database or another running process
is not in a state it can safely work with, `keyorix-server` exits with status 1 and one
line saying why, instead of starting in a weaker mode. This page lists those refusals:
the message you will see, what it means, how to fix it, and whether the fix is safe to do
on a live install.

[j7-troubleshooting.md](j7-troubleshooting.md) covers failures that are not refusals
(an unreachable database, an expired certificate). Start there when the server *runs* but
something is wrong. Start here when it **will not start**, or an `admin` command stops
with `Error:`.

**First step for any of them:** `keyorix-server admin diagnose --config ./keyorix.yaml`
runs the checks that start-up depends on and tells you which one fails, without opening a
listener. Most configuration refusals below also show up there.

## How to read an entry

- **Message** is what the process prints. In "Real output" blocks the text is pasted from
  a run of the native `keyorix-server` binary (SQLite, a throwaway data directory, a
  throwaway passphrase); the data directory is shown as `<datadir>` and unrelated start-up
  lines are cut (marked `...`). Entries marked **from code** were read from the source and
  not run: wording is exact, the surrounding lines are not.
- **Match** is the stable part of the message, with no paths, numbers or values. Search
  your logs for it. A test (`internal/refusaldocs`) fails when a Match text no longer
  exists in the Go sources, so an entry here cannot silently go stale.
- **In place?** says whether the fix is safe on a running install: *yes* (a config edit and
  a restart), *stop first* (the server must be down while you act), or *no* (read the linked
  procedure before touching anything, because a wrong move loses data or access).

Where the log line has a prefix (`Configuration is invalid:`, `startup validation:`,
`transport security:`, `failed to initialize core service:` ...) it names the stage that
refused; the prefix order is also the order the checks run, so an earlier prefix means the
later checks have not run yet.

Contents: [Configuration](#configuration) · [TLS](#tls) ·
[Database and storage](#database-and-storage) · [Keys and secret files](#keys-and-secret-files) ·
[Key files and DEK](#key-files-and-dek) ·
[Upgrade, schema epoch and rollback](#upgrade-schema-epoch-and-rollback) ·
[Security posture](#security-posture) · [HA and multiple replicas](#ha-and-multiple-replicas) ·
[Admin commands](#admin-commands) · [What this page does not cover](#what-this-page-does-not-cover)

---

## Configuration

These come from reading and validating `keyorix.yaml` and exit before anything is opened.
The fix is always an edit to the file (or env var) and a restart: **in place: yes**.

### Unknown or misplaced key

Real output:

```
Failed to load configuration: failed to unmarshal config: yaml: unmarshal errors:
  line 189: unknown key "webauthn" under security (check its spelling and section in docs/CONFIGURATION.md)
```

**Match:** `failed to unmarshal config`, `check its spelling and section in docs/CONFIGURATION.md`

**Cause.** The file is parsed strictly. A key that does not exist, is misspelled, or sits
under the wrong section is an error, not ignored. The message names the section the key
was found in (`at the top level of the file` for a top-level key; a section used in several
places is listed as `under server.grpc.tls or server.http.tls`). Earlier releases printed
the Go type instead (`field webauthn not found in type
config.SecurityConfig`, meaning "under `security:`").
**Fix.** Check the key's spelling and section against
[CONFIGURATION.md](../CONFIGURATION.md); `line N` is the line in your file. **In place:** yes.

### Wrong `storage.type`

Real output:

```
Configuration is invalid: invalid storage.type "sqllite": must be one of "local", "sqlite", "postgres", "postgresql", or "remote"
```

**Match:** `must be one of "local", "sqlite", "postgres", "postgresql", or "remote"`

**Cause.** Typo in `storage.type`. **Fix.** Use one of the listed values (`remote` is
refused for a server, see below). **In place:** yes. Same text as in
[j7](j7-troubleshooting.md#wrong-or-typod-config-value).

### `storage.type` missing — from code

```
storage.type is not set: no storage configuration found -- specify "local", "postgres", "postgresql", or "remote" explicitly
```

**Match:** `storage.type is not set: no storage configuration found`

**Cause.** Seen by tools that load the config without the server's own default. The server
itself treats a missing `storage:` block as local SQLite, so you meet this from `admin`
commands run against a config with no `storage.type`. **Fix.** Set `storage.type`. **In place:** yes.

### `storage.type: remote` on a server

Real output:

```
Configuration is invalid: storage.type: remote cannot back a server process: remote storage is a CLI/client mode only, not a deployable server backend (this includes a scheduler-only process with server.http.enabled and server.grpc.enabled both false -- server/main.go always starts its background schedulers regardless of either flag) — see ADR-083
```

**Match:** `remote cannot back a server process`

**Cause.** `remote` is the CLI's way of talking to a server; a server needs SQLite or
PostgreSQL. **Fix.** Put `remote` in the *client's* config only; give the server
`sqlite` or `postgres`. **In place:** yes. See [ADR-083](../adr-083-remote-storage-cli-only.md).

### Config file unreadable — from code

```
Failed to load configuration: failed to read config file "<path>": ...
```

**Match:** `failed to read config file`

**Cause.** The file named by `KEYORIX_CONFIG_PATH` (or `keyorix.yaml` in the working
directory) does not exist or cannot be read by the server's user. **Fix.** Fix the path or
the file's owner and mode. **In place:** yes.

### Listener enabled without a port

Real output:

```
Configuration is invalid: HTTP server is enabled but no port is specified
```

**Match:** `HTTP server is enabled but no port is specified`

**Cause.** `server.http.enabled: true` with no `port`. **Fix.** Add `port: "8080"` (the
gRPC equivalent is below). **In place:** yes.

### gRPC listener problems — from code

```
gRPC server is enabled but no port is specified
gRPC TLS is enabled but cert_file or key_file is missing
gRPC TLS auto_cert is not supported; provide cert_file and key_file
```

**Match:** `gRPC server is enabled but no port is specified`,
`gRPC TLS is enabled but cert_file or key_file is missing`

**Cause / fix.** Same as the HTTP entries; gRPC cannot use `auto_cert`. **In place:** yes.

### Unsupported language

Real output:

```
Configuration is invalid: unsupported language: xx. Supported languages: en, ru, es, fr, de
```

**Match:** `Supported languages: en, ru, es, fr, de`

**Cause / fix.** `locale.language` (or `fallback_language`) is not one of the five shown.
**In place:** yes.

### Wildcard CORS origin

Real output:

```
Configuration is invalid: server.http.allowed_origins must not contain "*" — list explicit origins (e.g. https://app.example.com); a wildcard origin defeats the CORS allowlist
```

**Match:** `a wildcard origin defeats the CORS allowlist`

**Cause / fix.** List each origin as `scheme://host[:port]`. Entries that are not origins, or
use a scheme other than http/https, are refused with a similar message. **In place:** yes.

### Other value checks — from code

Each of these is a single-line refusal with the offending key and value in the message; the
fix is to correct the value. **In place:** yes.

| Match | What it means |
|---|---|
| `exceeds the hard ceiling of` | `secrets.limits.max_secret_size` is above 1 MiB |
| `server.log.format: unknown value` | `server.log.format` must be `text` or `json` |
| `Failed to set up logging` | the logger could not be switched to `server.log.format` (the value itself was valid); report it as a bug. Earlier releases printed this under `Configuration is invalid:` |
| `storage.database.audit_durability: unknown value` | allowed: `strict`, `standard` |
| `is not a Go duration` | an expiry written as `7d`; use hours (`168h`) |
| `both metrics_token and metrics_token_file are set` | set exactly one |
| `autocert is enabled but no domains are specified` | `tls.auto_cert` needs `domains` |
| `connector(s) missing required "scope"` | every Connect connector needs `scope: project` or `platform` (ADR-082) |
| `cross-seam audience collision` | an SSO `client_id` is also a machine-federation audience; use distinct ones |
| `webauthn is enabled but rp_id is not set` | WebAuthn needs `rp_id` and `rp_origins` |
| `keyorix has no SAML assertion-replay cache` | a provider sets `insecure_allow_idp_initiated_saml` (or `allow_idp_initiated`); IdP-initiated SAML is not supported, remove the key |
| `refusing cross-host redirect to` | OIDC discovery was redirected to another host (a scheme downgrade is refused the same way); configure the issuer URL that serves its own discovery document |

### Webhook signing secret too short under `GODEBUG=fips140=only`

Real output (`GODEBUG=fips140=only`, `notifications.webhook.signing_secret` of 12 bytes):

```
Configuration is invalid: notifications.webhook.signing_secret (or KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET) is 12 bytes; under GODEBUG=fips140=only it must be at least 14 bytes (112 bits)
```

**Match:** `under GODEBUG=fips140=only it must be at least`

**Cause.** Go's FIPS 140-only mode refuses an HMAC key shorter than 112 bits, and the
webhook channel signs every payload with HMAC-SHA256 under this secret, so no signed
delivery could be sent. Only checked when the process runs with `GODEBUG=fips140=only` and
the webhook channel is enabled; outside that mode any length is accepted, as before.
**Fix.** Set a signing secret of at least 14 bytes (a random 32-byte value is better) in
`KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET` and the same value on the receiver, then restart.
**In place:** yes.

### Two sources for one secret

Real output (a master passphrase given both as a variable and a file):

```
Configuration is invalid: secret source misconfigured: both KEYORIX_MASTER_PASSWORD and KEYORIX_MASTER_PASSWORD_FILE are set; set exactly one (the secret may come from the environment or from a file, never both)
```

**Match:** `set exactly one (the secret may come from the environment or from a file, never both)`

**Cause.** A secret is available as `KEYORIX_<NAME>` and `KEYORIX_<NAME>_FILE`; both are set (an
empty-but-set variable counts). **Fix.** Unset one. **In place:** yes. See
[SELF_HOSTING.md](../SELF_HOSTING.md#3-configuration-env-and-secrets).

### Secret-name policy pattern does not compile

Real output (`secret_name_policy.enabled: true` with `pattern: "^(prod|dev"`, SQLite):

```
Invalid secret_name_policy: invalid secret name pattern: error parsing regexp: missing closing ): `^(?:^(prod|dev)$`
```

**Match:** `Invalid secret_name_policy`, `invalid secret name pattern`

**Cause.** `secret_name_policy.pattern` is not a valid RE2 regular expression. The value is not
checked while the file is read, so this is the one configuration refusal that comes **after**
the start-up lines (storage opened, encryption initialised) instead of as `Configuration is
invalid:`; nothing has been served yet. The pattern in the message is the one the server
compiled, wrapped as `^(?:...)$`. **Fix.** Correct the pattern (RE2 syntax: no look-ahead or
back-references), or set `secret_name_policy.enabled: false`, and restart. **In place:** yes.
[CONFIGURATION.md](../CONFIGURATION.md).

---

## TLS

### Cleartext listener with `require_transport_tls`

Real output:

```
startup validation warning: Database file <datadir>/keyorix.db does not exist yet — treating as first boot; it is created at 0600
Startup validation passed (config, file permissions, encryption keys, database).
HTTP server will bind http://127.0.0.1:18080
transport security: HTTP listener has no TLS but security.require_transport_tls is set: refusing to serve credentials/secrets in cleartext (enable tls or front it with a TLS-terminating proxy and unset the requirement)
```

**Match:** `listener has no TLS but security.require_transport_tls is set`

**Cause.** You asked for TLS to be mandatory and a listener has none. **Fix.** Enable
`server.http.tls` with a certificate and key, or terminate TLS in a proxy in front and set
`security.require_transport_tls: false` (the server then warns on every start that it is
serving cleartext). **In place:** yes. Note the earlier "Startup validation passed" line:
the TLS check runs after it. See [hardening guide](../security/hardening-guide.md).

### TLS enabled without certificate

Real output:

```
Configuration is invalid: TLS is enabled but cert_file or key_file is missing
```

**Match:** `TLS is enabled but cert_file or key_file is missing`

**Cause / fix.** `server.http.tls.enabled: true` needs both `cert_file` and `key_file`
(or `auto_cert` with `domains`). **In place:** yes.

### `auto_cert` in the air-gapped build

Message (air-gapped server build, `-tags noaws,noazure,nogcp`, `keyorix-server-airgap`):

```
Configuration is invalid: server.http.tls.auto_cert: true is not available in this build: the air-gapped server profile never contacts the internet, and automatic (ACME / Let's Encrypt) certificates need to reach a certificate authority. Remove server.http.tls.auto_cert and domains, and set server.http.tls.cert_file and key_file (certificate files issued by your internal CA), or use the full server build if the host can reach an ACME CA
```

**Match:** `server.http.tls.auto_cert: true is not available in this build`

**Cause.** ACME needs to reach a certificate authority on the internet, which the
air-gapped build never does. It is refused whether or not `tls.enabled` is set.
**Fix.** Remove `auto_cert` and `domains`; set `server.http.tls.cert_file` and `key_file`
to certificate files from your internal CA. The full build still accepts `auto_cert`.
**In place:** yes.

### Weak or misspelled cipher suite

Real output:

```
Configuration is invalid: server.http.tls.allowed_ciphers: "TLS_RSA_WITH_RC4_128_SHA" is not a recognized, secure TLS 1.2 cipher suite (allowed: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305) — weak/deprecated suites (RC4, 3DES, CBC-mode) are rejected outright
```

**Match:** `is not a recognized, secure TLS 1.2 cipher suite`

**Cause / fix.** `tls.allowed_ciphers` names a suite outside the allowed list. Use names
from the list, or remove the key. Under `tls_mode: strict` the list has no effect. It is a
configuration error, refused with the others before anything starts (earlier releases refused
it later, as `transport security: HTTP tls.allowed_ciphers: ...`,
after the `Startup validation passed` line). **In place:** yes.

### TLS certificate files — from code

```
no PEM certificates found in <path>
invalid TLS configuration: ...
```

**Match:** `no PEM certificates found in`

**Cause.** `cert_file` (or a CA bundle) exists but holds no PEM certificate, or the
certificate and key do not pair. **Fix.** Re-export the file as PEM; check that `cert_file`
and `key_file` belong together. **In place:** yes. (The server does *not* refuse an expired
certificate; see [j7](j7-troubleshooting.md#expired-tls-certificate).)

### Database TLS: verify mode without a CA

Real output:

```
Configuration is invalid: storage.database.ssl_mode is verify-full but no CA certificate is configured, so the database server's certificate would be checked against whatever trust store the process happens to find (PGSSLROOTCERT, ~/.postgresql/root.crt or the OS store) -- refusing to start. Set storage.database.ssl_root_cert to the PEM file of the CA that signed the database server's certificate, or to "system" to trust the OS CA store.
```

**Match:** `but no CA certificate is configured`

**Cause.** `verify-ca` or `verify-full` with no `ssl_root_cert`. **Fix.** Set
`storage.database.ssl_root_cert` to the CA file, or `system`. **In place:** yes.

### Database TLS: invalid `ssl_mode`

Real output:

```
Configuration is invalid: storage.database.ssl_mode "verfy-full" is not a valid sslmode; use one of: disable, allow, prefer, require, verify-ca, verify-full
```

**Match:** `is not a valid sslmode`

**Fix.** Use one of the listed modes. **In place:** yes.

### Database TLS: `ssl_root_cert` together with `dsn`

Real output:

```
Configuration is invalid: storage.database.ssl_root_cert cannot be combined with storage.database.dsn: the dsn is used as-is, so the key would be ignored; put sslrootcert=<path> in the dsn, or use host/name/user fields instead of dsn
```

**Match:** `cannot be combined with storage.database.dsn`

**Cause / fix.** A `dsn` is passed to the driver unchanged, so Keyorix's own TLS keys
cannot also apply. Put `sslrootcert=` in the dsn, or drop the dsn for the field form.
**In place:** yes.

### Database TLS: CA file problems and other TLS-vs-dsn conflicts — from code

| Match | What it means |
|---|---|
| `writable by group or others, refusing to trust it` | the CA file is group/other-writable; `chmod go-w` it |
| `contains a private key` | the CA file holds a private key; name the certificate only |
| `selects a PostgreSQL connection service` | `service=`/`servicefile=` in the dsn, or `PGSERVICE` set: the service file could override TLS settings; remove it |
| `storage.database.dsn already contains a password and` | a password in the dsn and in the separate password setting or variable the message names; keep one |
| `ssl_root_cert is set but storage.database.ssl_mode` | a CA with `ssl_mode` disable, or a CA file with allow/prefer: the driver never checks the certificate against it; set `ssl_mode: verify-full` or remove the CA |
| `storage.database.dsn sets sslrootcert but its effective sslmode` | the same in a dsn (no `sslmode` in the dsn means prefer); put `sslmode=verify-full` in the dsn or remove `sslrootcert` |
| `when dsn is set it is used as-is and ssl_mode is ignored` | `ssl_mode` is set beside a dsn that has no or a different `sslmode`; put `sslmode=` in the dsn, or remove `ssl_mode` |
| `the PostgreSQL driver's connection settings differ from what the TLS check validated` | the driver would read the TLS settings differently from Keyorix's own check (the message says what: for example the host name would not be verified); write `sslmode` and `sslrootcert` plainly in `storage.database` (or the dsn) |

**In place:** yes (config edit, restart).

### Port already in use

Real output:

```
HTTP server error: HTTP server failed to start: failed to bind HTTP listener: listen tcp 127.0.0.1:18080: bind: address already in use
exit=1
```

**Match:** `failed to bind HTTP listener`

**Cause.** Another process (often an earlier `keyorix-server`) holds the port.
**Fix.** `lsof -i :<port> -sTCP:LISTEN`, stop that process or change `port`. **In place:** yes.
(Unlike what j7 said in an earlier version, the process now exits with status 1.)

---

## Database and storage

### PostgreSQL unreachable

From [j7](j7-troubleshooting.md#postgres-unreachable) (real output there, not re-run here):

```
connect to postgres for server-presence check: failed to connect to `user=keyorix database=keyorix`:
	[::1]:59999 (localhost): dial error: dial tcp [::1]:59999: connect: connection refused
```

**Match:** `connect to postgres for server-presence check`

**Cause / fix.** See j7. The check names the host and port it tried. **In place:** yes.

### Database file missing when it must exist — from code

```
no database found at <path> (configured database.path: "<path>") and database.require_existing_path is set: ...
```

**Match:** `no database found at`

**Cause.** `database.require_existing_path` is set and the file is not there (a volume that
did not mount, or a wrong path). **Fix.** Fix the mount or path; do **not** remove the
setting to "make it start", that would create an empty database beside your real one.
**In place:** stop first.

### A migration cannot create a unique index — from code

```
cannot create unique index on <table> (<columns>): <n> pre-existing group(s) of rows already share a value under "<index>" — ...
```

**Match:** `cannot create unique index on`

**Cause.** An upgrade adds a uniqueness rule (for example case-folded names) and your data
already has duplicates. The upgrade stops before changing anything. **Fix.** The message
names the table and rows; rename or remove the duplicates (on a copy first), then start the
new version. **In place:** no, read [UPGRADING.md](../UPGRADING.md) and take a backup first.

### A migration step failed — from code

```
failed to initialize core service: failed to initialize storage: failed to migrate database: failed to migrate <table> table: <driver error>
```

**Match:** `failed to migrate database`

**Cause.** One of roughly seventy migration steps (one per table or index) failed (the
schema-epoch checks that run before them say `database schema check failed ... nothing was
migrated` instead, see [Upgrade, schema epoch and rollback](#upgrade-schema-epoch-and-rollback)); the last
part is the database's own error: usually permissions (the database user cannot `ALTER`/`CREATE`),
a full disk, or a read-only database. **Fix.** Take a backup, fix the cause the database
error names (DDL rights, disk space, a read-only mount), then restart: the migration runs
again from the start of start-up. **In place:** stop first.
[UPGRADING.md](../UPGRADING.md).

---

## Keys and secret files

### Master passphrase not provided

Real output:

```
failed to initialize core service: failed to initialize encryption: encryption is enabled with the password key provider but no master passphrase is available (KEYORIX_MASTER_PASSWORD is not set (and no --passphrase-fd/--passphrase-file/--passphrase-stdin was given; KEYORIX_MASTER_PASSWORD_FILE works too)); set KEYORIX_MASTER_PASSWORD, pass --passphrase-fd/--passphrase-file/--passphrase-stdin, or configure storage.encryption.key_provider (file/env/aws-kms)
```

**Match:** `no master passphrase is available`

**Cause.** Encryption is on and the server was not given the passphrase. **Fix.** Provide
it by one of the listed ways (a `0600` file is best). **In place:** yes.
[SELF_HOSTING.md](../SELF_HOSTING.md), section 4.

### Wrong master passphrase

Real output:

```
storage: opening existing SQLite database at <datadir>/keyorix.db (configured: "<datadir>/keyorix.db")
failed to initialize core service: failed to initialize encryption: KEK derivation from the master passphrase read from KEYORIX_MASTER_PASSWORD_FILE="<datadir>/mp" failed: failed to initialize key manager: failed to unwrap DEK — wrong passphrase or corrupted key file: GCM open failed: cipher: message authentication failed
```

When an interrupted (or unfinished) `rotate-kek` or `migrate-provider` left a file in the
key directory, the same error carries one more line per leftover, naming the file and the
recovery. Real output after a `migrate-provider --to-type file` whose new `key_provider`
was never put into the config (key paths are relative to the server's directory):

```
failed to initialize core service: failed to initialize encryption: KEK derivation from the master passphrase read from KEYORIX_MASTER_PASSWORD_FILE="<datadir>/mp" failed: failed to initialize key manager: failed to unwrap DEK — wrong passphrase or corrupted key file: GCM open failed: cipher: message authentication failed
  - keys/dek.key.migrate-backup.1793090500835024000-7a03da4d is the newest migrate-provider backup: if a migrate-provider was interrupted after it re-wrapped keys/dek.key (or finished and the configuration was not updated), keys/dek.key is wrapped under the TARGET provider. Set storage.encryption.key_provider to the provider you migrated to and start again; to go back afterwards, run `keyorix-server admin encryption migrate-provider --to-type <previous provider> --confirm`. Keep the backup until that works (docs/operator/key-rotation-runbook.md, "Interrupted rotate-kek or migrate-provider")
```

From code, for a `rotate-kek` killed after it re-wrapped the DEK and before it replaced the
salt (`<salt_path>.pending` present, no `<dek_path>.pending`):

```
  - keys/kek.salt.pending exists: a rotate-kek was interrupted after it re-wrapped keys/dek.key under the new passphrase and before it replaced keys/kek.salt. With the server stopped, run `mv keys/kek.salt.pending keys/kek.salt` and start with the NEW passphrase (docs/operator/key-rotation-runbook.md, "Interrupted rotate-kek or migrate-provider")
```

When `<dek_path>.pending` exists as well, the line says instead that a rotate-kek was
interrupted before it replaced the DEK: start with the **previous** passphrase, re-run
`rotate-kek`, and do not rename either file.

**Match:** `wrong passphrase or corrupted key file`, `KEK derivation from the master passphrase read from`, `is the newest migrate-provider backup`, `a rotate-kek was interrupted after it re-wrapped`, `a rotate-kek was interrupted before it replaced`

**Cause.** The passphrase does not open the wrapped DEK (`storage.encryption.dek_path`,
`keys/dek.key` in the config `admin init` writes), or the DEK or the salt
(`storage.encryption.salt_path`, `keys/kek.salt`) is damaged or from a different install, or
a `rotate-kek` / `migrate-provider` left the DEK wrapped under a KEK the configuration does
not produce yet (the extra lines above). **Key-file state:** start-up checks the key set
*before* it tries the passphrase, so a missing or mixed file is refused earlier with
`key file consistency: ...` (see [Key file set incomplete or mixed](#key-file-set-incomplete-or-mixed--from-code))
or with the file-permission audit ([A key file is missing on a later start](#a-key-file-is-missing-on-a-later-start)),
not with this message. Reaching this one means `keys/dek.key` and `keys/kek.salt` are both present and
consistent with `keyset.manifest.json` (or the manifest is absent): the passphrase, or a
leftover of an interrupted key operation, is the remaining suspect. The message names the source the
passphrase was read from (`--passphrase-fd N`, `--passphrase-file "<path>"`,
`--passphrase-stdin`, `KEYORIX_MASTER_PASSWORD_FILE="<path>"` or `KEYORIX_MASTER_PASSWORD`; a
relative path is not printed, the message says `a relative path, not shown: it may be the secret itself`):
check that it is the one you meant, since a leftover variable in the environment is easy to miss. **Fix.** If the
message has a leftover line, follow it (full procedure:
[key-rotation-runbook.md](key-rotation-runbook.md#interrupted-rotate-kek-or-migrate-provider)) and keep
the leftover file until the server starts. Otherwise try the right passphrase first.
If you changed it deliberately, check that `admin encryption rotate-kek` finished. If a key
file is damaged, restore the matching DEK **and** salt from backup. **Never**
delete the key files to "start fresh": a new key cannot open existing data.
**In place:** no. [j6-key-rotation.md](j6-key-rotation.md), [drill-backup-restore.md](drill-backup-restore.md).

### Key file readable by others (explicit `enable_file_permission_check`)

Real output (`keys/dek.key` at mode 644, `security.enable_file_permission_check: true` set;
the config `admin init` writes also has `auto_fix_file_permissions: true`, which resets a wrong
mode at every start, so the block was made with it set to `false`):

```
[WARN] File keys/dek.key has mode 644 but expected 600
startup validation: file permission validation failed: permissions or ownership audit found unresolved issues: File keys/dek.key has mode 644 but expected 600 -- fix each file named (chmod to the expected mode, chown to the server's user), restore a missing one from backup, or set security.auto_fix_file_permissions: true to fix modes and owners at start
```

**Match:** `permissions or ownership audit found unresolved issues`

**Cause.** The refusal lists every file and what is wrong with it (the untimestamped
`[WARN]` line above repeats the same). Here a key file is group/other-readable; a file
owned by another uid reads `is owned by uid N, expected uid M`. The same refusal covers a
missing key file or database that other files say should exist (next entry).
**Fix.** `chmod 600` the named file (and `chown` it to the server's user). With
`security.enable_file_permission_check` absent, Keyorix applies the same rule to key
material by default; on a Kubernetes Secret mount use `defaultMode: 0400`. **In place:**
yes: permissions only. See the [hardening guide](../security/hardening-guide.md).

### A key file is missing on a later start

Real output (`keys/kek.salt` deleted, the database and `keys/dek.key` present,
`security.enable_file_permission_check: true`): the same refusal as above, naming the file:

```
[WARN] Cannot open file keys/kek.salt: open keys/kek.salt: no such file or directory
startup validation: file permission validation failed: permissions or ownership audit found unresolved issues: cannot open keys/kek.salt (no such file or directory) -- fix each file named (chmod to the expected mode, chown to the server's user), restore a missing one from backup, or set security.auto_fix_file_permissions: true to fix modes and owners at start
```

**Match:** `permissions or ownership audit found unresolved issues`

**Cause.** The database exists, so this is not a first boot, but `keys/kek.salt` (or `keys/dek.key`)
is gone: an unmounted key volume, a restore that missed a file, or a deletion.
**Fix.** Restore **both** key files from the same backup, or mount the right volume. Do not
start with the files missing: with the check off, the server would generate a *new*
salt and key over your encrypted data, and every value would become unreadable.
**In place:** no. [SELF_HOSTING.md](../SELF_HOSTING.md), sections 4 and 5.

### Explicit `enable_file_permission_check` on a brand-new install

Real output (`security.enable_file_permission_check: true` written before the first start;
no key file and no database yet):

```
startup validation: file permission validation failed: no key material exists (keys/kek.salt, keys/dek.key) and there is no local database: security.enable_file_permission_check is set explicitly, and an explicit setting never treats missing key material as a first boot, because a key volume that failed to mount looks the same and starting would generate new keys over encrypted data. On a brand-new install, remove security.enable_file_permission_check from the config for the first start (the default runs the same checks and generates the keys), then set it again; on an existing install, mount or restore the key files (all of them, from one backup)
```

**Match:** `no key material exists`, `an explicit setting never treats missing key material as a first boot`

**Cause.** The explicit setting is strict on purpose: from the files alone a new install and
an install whose key volume did not mount look the same. **Fix.** New install: remove the
key for the first start (the ADR-112 default already enforces the check and generates the
keys), then add it back. Existing install: mount or restore the key files. `admin validate`
on a config without the key reports the same state as "looks like a brand-new install".
**In place:** yes for a new install; **no** for an existing one (restore first).

### Key file set incomplete or mixed — from code

```
key file consistency: key material is an incomplete set: present (<files>); missing (<files>) — this is not a state any provisioning path produces; restore the full set from one backup, or remove the partial files and let first-boot generation recreate them
key file consistency: key material does not match the key-set manifest <dir>/keyset.manifest.json: <file> (recorded by <operation> at generation <n>) — these files come from a different generation than the rest of the set ...
```

**Match:** `key material is an incomplete set`, `key material does not match the key-set manifest`

**Cause.** Only some files of one key set are present, or a file's content matches neither the
hash the key-set manifest (`keyset.manifest.json`, next to the DEK) records for it nor a staged
one: it comes from another backup or generation (typically a partial restore, one file copied in
from an older backup, or a key operation run with an older `keyorix-server` binary that does not
maintain the manifest). The check compares content, so how the files were copied (`cp`, `kubectl
cp`, `rsync`) and their modification times play no part. **Fix.** Restore the whole set from one
backup with `keyorix-server admin restore` (it records a new manifest). If you replaced the named
files deliberately and they do belong together, remove `keyset.manifest.json`: the next start
adopts the current files with a WARN and an `encryption.keyset_manifest_adopted` audit event. "Remove the
partial files and let first boot recreate them" is only right on an install that has **no data
yet**. **In place:** no.

### Key operation interrupted mid-commit — from code

```
key file consistency: key material is incoherent: an interrupted <operation> (generation <n> in the key-set manifest <dir>/keyset.manifest.json) already replaced <files> but not <files>, and no staging file holds the content it was about to write ...
```

**Match:** `key material is incoherent`

**Cause.** A key operation (rotate-kek, rotate, migrate-provider) was interrupted after it had replaced
some of the active key files and before the rest, and boot cannot complete it: the key-set
manifest records the content each file was about to get, and no staging file holds it. The
active files belong to two generations, so the first decrypt would fail. (An interrupted
rotate-kek whose `kek.salt.pending` is intact is **not** refused: the server finishes the
rename at boot, logs a WARN, records an `encryption.keyset_rotation_finished` audit event,
and from then on the master passphrase is the **new** one given to rotate-kek. A rotation
interrupted before it changed any active file only logs that its staging files can be
deleted.) An interrupted `admin restore` is not reported here: it installs its key files and
the key-set manifest through its restore journal, and the journal check below runs first.
**Fix.** Re-run the operation, or restore the whole set from one backup with `keyorix-server
admin restore --overwrite-existing`. **In place:** no.

### Interrupted restore — from code

```
an interrupted `admin restore` left its journal at <dir>/.keyorix-restore-journal.json: the key files and the database may not match until it is resolved. Stop every server on this data, then run `keyorix-server admin restore --recover` (it finishes the restore if its data was committed, and undoes it otherwise)
```

**Match:** `left its journal at`

**Cause.** An `admin restore` was killed (or failed to install a file) after it staged the
archive's key files and data, so the key files and the data may be from different points in
time. `admin backup`, a new `admin restore` and the key operations that write key files
(`admin encryption rotate`, `rotate-kek`, `upgrade-aad`, `migrate-provider`, `init`) refuse with
the same message. This check runs before the key-set checks above, so a half-installed restore
is reported here, not as a mixed or incomplete key set. **Fix.** Stop
every server on this data and run `keyorix-server admin restore --recover`: it rolls the
restore forward if its data was committed and back otherwise, and refuses (changing
nothing) when a staged key file is missing or altered
([restore-failure-modes.md](restore-failure-modes.md)). Rolling forward also installs the
restored set's `keyset.manifest.json`, so the next start's key-set check passes. Run it with the same config and
working directory as the restore. Do not delete the journal by hand.
**In place:** yes, `--recover`.

### Key files readable by others, or owned by another account — from code

```
key file security: key material is readable beyond its owner: <path> (mode 644) — refusing to start (chmod 600 and chown the files to the server's user, or set security.insecure_allow_unsafe_file_permissions to override)
key file security: key material is owned by an account the server does not trust: <path> (owned by uid 1000; the server runs as uid 1001 and trusts only that uid and root, because the owner can replace the file) — refusing to start (...)
```

**Match:** `key material is readable beyond its owner`, `key material is owned by an account the server does not trust`, `refusing to start (chmod 600 and chown the files to the server's user`

Not reproduced natively. On SQLite, with `auto_fix_file_permissions: false` and a `0644`
`keys/dek.key` or `certs/server.key`, the earlier `permissions or ownership audit found
unresolved issues` refusal ([above](#key-file-readable-by-others-explicit-enable_file_permission_check))
stopped the start before this check ran, with or without `enable_file_permission_check` set.
A wrong owner needs a second account to `chown` to. The wording is read from the source.

**Cause.** This is the always-on second check of the wrapped DEK, the KEK salt and the TLS
private keys. The first form: group or other can read the file. The second (#3410): the
file belongs to an account other than the server's own uid and root, and whoever owns a
file can rewrite it, whatever its mode. **Fix.** `chmod 600` the file and
`chown <server user> <file>` (or `chown root`); prefer that to the override. On Compose the
key volume is created owned by the server's uid 1001, and on Helm the files are written by
the pod's uid, so only a hand-copied or hand-restored file normally shows this. With
`security.enable_file_permission_check` unset, a TLS key only warns; in the ADR-112
upgrade grace period, with the check off or with the override, both forms only warn.
**In place:** yes.

### Key file contents invalid — from code

| Match | What it means |
|---|---|
| `KEK salt file not found` | `storage.encryption.salt_path` points at nothing |
| `wrapped DEK file not found` | `storage.encryption.dek_path` points at nothing |
| `has invalid size` | salt is not 32 bytes: truncated or wrong file |
| `to be a valid wrapped key` | the wrapped DEK file is too small to be one: truncated |

**In place:** no: restore from backup, do not recreate.

### Secret file too open

Real output (`KEYORIX_MASTER_PASSWORD_FILE=<datadir>/mp` at mode 644):

```
secret file security: KEYORIX_MASTER_PASSWORD_FILE="<datadir>/mp": mode 0644 is too open (accessible to other users) -- refusing to trust it; chmod 0600/0400, or mount it from the orchestrator owned by root with a group the process belongs to (fsGroup / group_add) and mode 0440 (key material: security.insecure_allow_unsafe_file_permissions does not apply to it; the server refuses it wherever it reads it, so fix the file) -- refused until the file is fixed
```

When the variable holds a relative path, the message does not print it (it may be the secret
itself): `KEYORIX_MASTER_PASSWORD_FILE (a relative path, not shown: it may be the secret itself): mode 0644 is too open ...`.

For a file that is not key material (database password, bootstrap token ...) the end reads
`-- refused until the file is fixed (for the files that are not key
material, security.insecure_allow_unsafe_file_permissions: true turns this into a warning)`.

**Match:** `refusing to trust it; chmod 0600/0400`, `refused until the file is fixed`

**Cause.** A file behind a `KEYORIX_*_FILE` variable is readable by others, or (#3393) owned
by an account other than the server's user and root. **Fix.** `chmod 0600` (and `chown`);
on Kubernetes use `fsGroup` with mode `0440`. The override only helps for files that are
not key material: the master passphrase, env KEK and Shamir share files are refused again
where they are read, with no override (with the override set, this check warns and the
server stops with `no master passphrase is available (... mode 0644 is too open ...)`).
**In place:** yes.

### Another process holds the key lock

Real output (second server started on the same data directory):

```
failed to initialize core service: failed to initialize encryption: failed to acquire the encryption key lock: another process already holds the DEK lock (a live server, or a concurrent rotation): resource temporarily unavailable
```

**Match:** `another process already holds the DEK lock`

**Cause.** A server (possibly one you thought you stopped), or an `admin encryption`
operation, holds `dek.lock`. Two servers may not share one SQLite data directory.
**Fix.** Find and stop the other process (`lsof <datadir>/dek.lock`), then start again.
For several replicas on one PostgreSQL database, follow the supported topology in
ADR-039 rather than pointing two servers at one key directory. **In place:** stop first.
[ADR-039](../adr-039-ha-deployment.md), [j7](j7-troubleshooting.md#port-already-in-use).

### KMS context fallback no longer needed — from code

```
failed to initialize core service: failed to initialize encryption: ... aws-kms key provider: storage.encryption.key_provider.insecure_allow_kms_context_fallback is set, but the wrapped KEK already decrypts with its encryption context: there is nothing left to migrate, so the flag is no longer needed and can be removed (it only keeps the unbound no-context decrypt path open) -- refusing to start until it is removed
```

**Match:** `the wrapped KEK already decrypts with its encryption context`

**Cause.** `insecure_allow_kms_context_fallback` (aws-kms, gcp-kms) lets a wrapped KEK that
has no `kms_encryption_context` binding yet still open while you migrate it. The stored
KEK now opens *with* its context, so the migration
(`keyorix-server admin encryption migrate-provider --to-kms-encryption-context=...`) is done and the flag
only keeps the weaker path open: a blob someone planted under the shared KMS key with no
context would still unwrap. Since #3398 the server refuses instead of running with it.
**Fix.** Remove `insecure_allow_kms_context_fallback` from `storage.encryption.key_provider`
(and from any `fallbacks[]` entry for the same key), restart. Nothing else changes: the KEK
already opens without the flag. With a legacy KEK that still needs the flag, the server
starts as before and logs every fallback decrypt. **In place:** yes.

### Secret file or passphrase file content — from code

| Match | What it means |
|---|---|
| `secret file is empty` | the file behind `KEYORIX_*_FILE` is empty |
| `is group- or world-readable (mode` | `--passphrase-file` is not `0600` |
| `(the user the server runs as) or to root` | `--passphrase-file`, or the KEK file of `key_provider: file`, is owned by an account other than the server's user and root (#3410: that account could replace it); the message names the owner uid. `chown` it. No override |
| `refusing to trust it as key material` | the KEK file of `key_provider: file` is not `0600`/`0400`; `chmod` it. No override |
| `owner cannot be determined -- refusing to trust it` | the owner check could not read who owns the file (the file's status carries no unix owner), so it fails closed, as for a foreign owner; no override. Not run: a regular file on Linux or macOS always reports its owner, so the message is not reachable from the native binary here; it is read from the source. If you meet it, the file is on a filesystem that does not report owners: move it to a local one |
| `secret-value encryption did not engage` | encryption is configured but did not start; the server refuses to store secrets in plaintext. Check the key provider settings and earlier log lines |
| `refusing to start rather than leave a webhook credential unencrypted at rest` | the start-up pass that encrypts stored notification URLs failed; fix the database error shown first (permissions, disk) and restart |
| `DEK-rotation crash recovery failed` | an interrupted `admin encryption rotate` could not be completed on start; do **not** delete files; see [j6](j6-key-rotation.md) |

---

## Key files and DEK

Refusals about generating, replacing or moving key material: the wrapped DEK, the KEK salt
and the key set a Secret carries. The refusals about the *state* of existing key files
(permissions, owner, missing or mixed files) are in [Keys and secret files](#keys-and-secret-files).
All of them stop before any key file is written or replaced.

Key paths in the blocks below are relative because the commands ran with the data directory
as the working directory (`dek_path: "keys/dek.key"`, the value `admin init` writes). The
PostgreSQL blocks come from a database created for the run (`storage.type: postgres`).

### No wrapped DEK, but the database already holds encrypted data

Real output (PostgreSQL, `storage.encryption.key_dir_lock: database`, `keys/` emptied after a
first start had recorded the DEK epoch):

```
failed to initialize core service: failed to initialize encryption: no wrapped DEK at "keys/dek.key", but the database already records a DEK epoch (another replica generated the deployment's DEK): refusing to generate a new DEK. With storage.encryption.key_dir_lock: database every replica must read the same key files (one shared volume, or the same mounted Secret); copy the key set from a running replica or restore it from backup (docs/multi-replica-keys.md)
```

The same refusal when the database holds secret values but no recorded epoch (real output;
the epoch row was deleted and one `secret_versions` row inserted for the run):

```
failed to initialize core service: failed to initialize encryption: no wrapped DEK at "keys/dek.key", but the database already holds encrypted secret versions: refusing to generate a new DEK. With storage.encryption.key_dir_lock: database every replica must read the same key files (one shared volume, or the same mounted Secret); copy the key set from a running replica or restore it from backup (docs/multi-replica-keys.md)
```

**Match:** `but the database already records a DEK epoch`, `but the database already holds encrypted secret versions`

**Cause.** With `key_dir_lock: database` the replicas of one deployment share one DEK, and each
must read the same key files. This replica found no wrapped DEK at `dek_path` (a per-pod volume
that is empty, a Secret that did not mount, a wrong path) while the database already holds data
under a DEK. Generating a new one here would split the deployment into replicas writing under
two keys, so the server stops instead. The check runs only when the file is missing, under the
key-initialisation lock, so two replicas starting at once on empty directories cannot both pass.
**Fix.** Give this replica the deployment's key set: mount the shared volume or the same Secret,
copy the files from a running replica, or restore them from your key backup (all files, from
one backup). Do **not** remove the database rows or point `dek_path` at a new directory to "make
it start". **In place:** no. [multi-replica-keys.md](../multi-replica-keys.md#design-storageencryptionkey_dir_lock-database),
[SELF_HOSTING.md](../SELF_HOSTING.md), [drill-backup-restore.md](drill-backup-restore.md).

### Key-initialisation lock lost — from code

```
the key-initialisation lock was lost while this replica was generating or recovering the key files, so another replica may have written them at the same time; refusing to start with keys that may not match the key directory -- restart to load the files now on disk (docs/multi-replica-keys.md)
```

**Match:** `the key-initialisation lock was lost while this replica was generating or recovering the key files`

Not run: it needs the PostgreSQL connection that holds the lock to die while the key files are
being written, which the native run cannot arrange on demand. Wording is exact; the line after
the message (a parenthesised detail on why the lock was lost) is not shown.

**Cause.** The advisory lock that keeps replicas from generating or recovering the key files at
the same time was lost (the database connection dropped, or the database restarted) in the middle
of that work, so another replica may have written the same files. **Fix.** Restart the server: it
reads the files now on disk instead of trusting what it just wrote. If it then refuses with a
mixed or incomplete key set, follow [Key file set incomplete or mixed](#key-file-set-incomplete-or-mixed--from-code).
**In place:** yes, a restart; **no** if the next start names a key-set problem.
[multi-replica-keys.md](../multi-replica-keys.md).

### DEK rotation refused under `--force`

Real output (PostgreSQL, a server running on the database, `admin encryption rotate --force --confirm`):

```
WARNING: could not acquire this database's exclusive lock (another process holds this database (a live server, or another admin command) via postgres advisory lock 872342) — proceeding anyway because --force was given. A live server or another admin command may be concurrently using this database; this command is not protected against that race.
Error: refusing to rotate the DEK: could not acquire this database's exclusive lock (another process holds this database (a live server, or another admin command) via postgres advisory lock 872342), and --force cannot override it for a DEK rotation on PostgreSQL: a replica on another host that is still running would commit rows under the old DEK after the sweep, and they become undecryptable once the old DEK is gone. Stop every server that uses this database (every replica, on every host), then retry without --force; a lock left by a dead connection is released when PostgreSQL closes it (emergency SQL: SELECT pid, granted, mode FROM pg_locks WHERE locktype = 'advisory' AND objid = 872342; then, only for a connection that is not a live replica, SELECT pg_terminate_backend(<pid>))
```

With `storage.encryption.key_dir_lock: database` the command stops one step earlier, at the lock
itself, with a message that ends the same way (real output):

```
Error: could not acquire this database's exclusive lock (another process holds this database (a live server, or another admin command) via postgres advisory lock 872342), and --force cannot override it with storage.encryption.key_dir_lock: database: running replicas hold no key-directory lock, so this lock is what keeps admin commands away from them. Stop every replica first (scale to 0); a lock left by a dead connection is released when PostgreSQL closes it (emergency SQL: SELECT pid, granted, mode FROM pg_locks WHERE locktype = 'advisory' AND objid = 872342; then, only for a connection that is not a live replica, SELECT pg_terminate_backend(<pid>))
```

**Match:** `and --force cannot override it for a DEK rotation on PostgreSQL`, `and --force cannot override it with storage.encryption.key_dir_lock: database`

**Cause.** A server (or another admin command) holds this database's presence lock, and
`--force` got the command past it. The key-directory lock (`dek.lock`) only protects one host's
key directory, so a replica on another host would keep committing rows under the old DEK, and
those rows become unreadable once the old DEK is gone. A dry run is not refused; every
other `admin` command still accepts `--force` as described in
[An admin command while the server is running](#an-admin-command-while-the-server-is-running).
**Fix.** Stop every server that uses this database, on every host, and run the rotation again
**without** `--force`. If the lock is held by a connection whose server is gone, the emergency
SQL in the message names the session; terminate only a session that is not a live replica.
**In place:** stop first (every replica). [key-rotation-runbook.md](key-rotation-runbook.md),
[multi-replica-keys.md](../multi-replica-keys.md#rotation-in-secret-mode).

### `migrate-provider cleanup` while the key directory is in use

Real output (PostgreSQL, a server running on the database, `admin encryption migrate-provider cleanup --confirm --force`;
without `--force` the command stops earlier at the database lock, see the previous entry):

```
WARNING: could not acquire this database's exclusive lock (another process holds this database (a live server, or another admin command) via postgres advisory lock 872342) — proceeding anyway because --force was given. A live server or another admin command may be concurrently using this database; this command is not protected against that race.
Error: refusing to clean up migrate-backup files: another process already holds the DEK lock (a live server, or a concurrent rotation): resource temporarily unavailable — a live server or an in-progress migrate-provider or rotation is using this key directory, and a running migration may still need its backup to restore the DEK. Stop the server, or let the other command finish, then retry
```

**Match:** `refusing to clean up migrate-backup files`

**Cause.** `cleanup` deletes the `<dek_path>.migrate-backup.*` files, and a `migrate-provider`
that is still running (or was killed and not yet recovered) may need one to restore the DEK. It
takes the key-directory lock exclusively, and a live server holds it. `--force` only goes past
the database lock, never this one. **Fix.** Stop the server (or wait for the other command),
then run it again; run it with `--dry-run` first to see what it would delete. Delete the
backups only once the server has started with the new provider. **In place:** stop first.
[key-rotation-runbook.md](key-rotation-runbook.md#interrupted-rotate-kek-or-migrate-provider).

### `key-secret`: where the key material may go

`admin encryption key-secret generate` and `export` write a Kubernetes Secret manifest that
holds the wrapped DEK and the KEK salt. They refuse any destination where that manifest would
end up in a log or over another key set, and `unpack` refuses a directory that is not empty.

Real output (`--out -` with `KUBERNETES_SERVICE_HOST` set, as it is inside any pod):

```
Error: --out -: refusing to write key material to stdout inside a Kubernetes pod, where stdout is collected as the pod log; write it to a file (--out <path>) on a volume you control
```

Real output (`--out -` with `JOURNAL_STREAM` set, as it is for a systemd service whose output goes to the journal):

```
Error: --out -: refusing to write key material to stdout under systemd, where stdout goes to the journal; use --out <path>
```

Real output (`--out` naming a file that exists, here from running `generate` twice with the same path):

```
Error: --out keys-secret.yaml already exists: refusing to overwrite it (it may hold the only copy of a key set)
```

Real output (`unpack --in keys-secret.yaml --dir keys` into the live key directory):

```
Error: --dir keys is not empty: refusing to write a key set over another one (an interrupted rotation's workspace holds the only copy of its new DEK)
```

From code (not run: a terminal as stdout needs a pseudo-terminal, which the capture
environment could not open):

```
Error: --out -: refusing to print key material to a terminal; pipe it (… --out - | kubectl create -f -) or use --out <path>
```

**Match:** `refusing to write key material to stdout inside a Kubernetes pod`, `refusing to write key material to stdout under systemd`, `refusing to print key material to a terminal`, `already exists: refusing to overwrite it (it may hold the only copy of a key set)`, `is not empty: refusing to write a key set over another one`

**Cause.** `--out -` writes the manifest to stdout, which is safe only when stdout is a pipe you
control: a terminal keeps it in scrollback, the container runtime collects a pod's stdout as the
pod log, and journald records a service's. `--out <path>` never replaces a file, because the
file may be the only copy of a key set; `unpack` never writes over a directory that already
holds files, because the workspace of an interrupted rotation holds the only copy of its new DEK.
**Fix.** Write to a new file (`--out keyorix-keys-1.yaml`, created `0600`), or pipe stdout
(`... --out - | kubectl create -f -`, from a shell that is not inside a pod or a service). Pick
a new path rather than deleting an old file you have not checked; unpack into an empty or new
directory. **In place:** yes: nothing was written.
[multi-replica-keys.md](../multi-replica-keys.md#first-install-who-creates-the-first-key).

---

## Upgrade, schema epoch and rollback

### Database newer than this binary (no compatibility floor)

Real output, re-captured on 2026-10-30 at schema epoch 9 (`currentSchemaEpoch` in
`internal/storage/factory_schema_epoch.go`; `schema_epoch` edited to 999 and the floor row
deleted, to stand in for a newer release):

```
storage: opening existing SQLite database at <datadir>/keyorix.db (configured: "<datadir>/keyorix.db")
failed to initialize core service: failed to initialize storage: database schema check failed (checked before migrating; nothing was migrated): database schema epoch 999 is newer than this binary's schema epoch 9 (recorded at 2026-10-30T18:28:16+01:00, 20m48s ago) -- this database was migrated by a newer version of Keyorix. Two things produce this, and this process cannot tell them apart on its own: (a) a rolling upgrade in progress -- ... (b) this binary was downgraded against a schema a newer version already migrated -- if so, upgrade this binary to match, or restore a backup taken before the newer version ran. No minimum compatible schema epoch is recorded, so nothing declares this schema safe for an older binary. Refusing to start is the safe default in both cases (ADR-097, ADR-101)
```

**Match:** `is newer than this binary's schema epoch`, `checked before migrating; nothing was migrated`

**Cause.** A newer Keyorix has already migrated this database. **Fix.** (a) During a rolling
upgrade this pod's old image is about to be replaced: wait. (b) After a downgrade: run the
newer version again, or restore a backup taken *before* it first ran. Do **not** edit
`system_metadata` to make the number match: the older code does not understand the newer
schema. **In place:** no. [UPGRADING.md §7 Rollback](../UPGRADING.md#7-rollback),
[ADR-097](../adr-097-schema-epoch-downgrade-guard.md).

### Database declares a compatibility floor above this binary

Real output, re-captured on 2026-10-30 at schema epoch 9 (floor edited to 999):

```
failed to initialize core service: failed to initialize storage: database schema check failed (checked before migrating; nothing was migrated): database declares a minimum compatible schema epoch of 999 (database schema epoch 9), above this binary's schema epoch 9 (floor recorded at 2026-10-30T17:49:10Z, 4s ago) -- a migration this database has already applied was declared unsafe for binaries this old, so this binary must not run against it. If this is a rolling upgrade, this pod is expected to be replaced by the new image; if this binary was rolled back, roll forward to a version with schema epoch 999 or later, or restore a backup taken before the newer version ran. Refusing to start (ADR-101)
```

**Match:** `database declares a minimum compatible schema epoch of`

**Cause.** A migration this database already ran says older binaries must not use it: the
dangerous rollback. **Fix.** Roll forward to a release at or above the stated epoch, or
restore a pre-upgrade backup. **In place:** no. The message prints the numbers it saw; in
this reproduction both were hand-edited, in a real rollback they come from the release.

Real output of that rollback: a v0.96.3 install (SQLite), migrated by a schema-epoch-9 build
with `admin migrate`, then the v0.96.3 binary started again. The upgrade raised the
recorded floor from 2 to 3. v0.96.x words the prefix differently (`failed to migrate
database:`):

```
failed to initialize core service: failed to initialize storage: failed to migrate database: database declares a minimum compatible schema epoch of 3 (database schema epoch 9), above this binary's schema epoch 2 (floor recorded at 2026-10-30T18:53:27+01:00, 0s ago) -- a migration this database has already applied was declared unsafe for binaries this old, so this binary must not run against it. If this is a rolling upgrade, this pod is expected to be replaced by the new image; if this binary was rolled back, roll forward to a version with schema epoch 3 or later, or restore a backup taken before the newer version ran. Refusing to start (ADR-101)
```

Floor 3 is why: v0.96.x misreads the v2 audit retention anchor and never writes the suspend
clear-copies marker ([UPGRADING.md §6q](../UPGRADING.md#6q-compatibility-floor-3-v096x-cannot-run-against-an-upgraded-database)).
[UPGRADING.md §7](../UPGRADING.md#7-rollback), [ADR-101](../adr-101-schema-epoch-compatibility-floor.md).

### Stored epoch unreadable — from code

```
stored schema epoch "<value>" is not a valid integer -- refusing to start rather than guess whether this database is ahead of this binary (ADR-097)
stored minimum compatible schema epoch <n> is below 1, which no version of Keyorix writes -- refusing to start rather than trust a corrupted compatibility floor (ADR-101)
```

**Match:** `is not a valid integer -- refusing to start rather than guess`,
`is below 1, which no version of Keyorix`

**Cause.** `system_metadata.schema_epoch` or `schema_min_compatible_epoch` was edited or
corrupted. **Fix.** Restore the database from backup; do not hand-edit. **In place:** no.

### Restore: backup is from a newer version — from code

```
Error: backup archive's schema epoch <n> is newer than this binary's schema epoch <m> (ADR-097) -- this backup was taken by a newer version of Keyorix; upgrade this binary before restoring it
```

**Match:** `backup archive's schema epoch`

**Fix.** Restore with the same or a newer release than took the backup. **In place:** yes
(nothing was changed).

### Restore: older than this host's own history (rollback protection)

Real output (restoring a backup taken before two `admin encryption rotate` runs, which each add audit events, over the same data directory with `--overwrite-existing`; backups taken later add only the backup tool's own bookkeeping events, which do not count as "behind"):

```
Error: refusing to restore: this backup's audit trail (15 event(s)) is 2 event(s) BEHIND this host's own last known state (18 event(s)) -- restoring it would silently un-revoke any user/credential access revoked since this backup was taken. Pass --allow-rollback if this is a genuine disaster-recovery restore of an intentionally older backup
```

**Match:** `refusing to restore: this backup's audit trail`

**Cause.** The archive has fewer audit events than this host already holds, so restoring it
would bring back access that was revoked since. **Fix.** Use a newer backup. For a real
disaster recovery onto this host, `--allow-rollback` records the override in the audit
trail; afterwards, re-check who has access. **In place:** no.
[drill-backup-restore.md](drill-backup-restore.md), [UPGRADING.md §4](../UPGRADING.md#4-backup-format-v1-vs-v2).

---

## Security posture

Settings named `insecure_*` (and the ones the secure-by-default baseline, ADR-112, turned on)
do not make the server refuse to start when you relax them: each one in effect prints a
`WARNING: <key> is in effect` line on **every** start. The refusals in this group are about
a *secure* setting that cannot be satisfied.

Look at the first lines of a start:

```
WARNING: security.insecure_allow_unsafe_file_permissions is in effect (true; config: security.insecure_allow_unsafe_file_permissions) — lets group/other-readable key material pass enforceKeyFilePermissions/ValidateStartup instead of failing closed
WARNING: security.insecure_allow_cleartext_transport is in effect (true) — allows bearer tokens/secret values over cleartext HTTP/gRPC. That is the setting's registry name, not a config key: security.require_transport_tls is false or not set (false is its default); set security.require_transport_tls: true to refuse a listener without TLS
```

The text before `is in effect` is the setting's registry name. When it is also a config key,
the keys after `config:` are what you write in `keyorix.yaml`. When it is not (the line says
`not a config key`), the end of the line names the key that controls it; writing the
registry name itself is rejected as an unknown key (see the first entry). A line can appear
for a key you never wrote: some of these states are the default when a key is absent.

### Cleartext listener under `require_transport_tls`

See [TLS](#cleartext-listener-with-require_transport_tls).

### Skipping read audit under a compliance profile — from code (not reachable today)

```
storage.database.insecure_audit_skip_reads: true is refused while the compliance profile <name> is active: ...
```

**Match:** `is refused while the compliance profile`

The list of compliance profiles is empty in this release, so the refusal cannot occur yet.
Listed so it is not a surprise when the first profile ships.

### FIPS 140-only boot self-test failed — from code

```
Refusing to start: fips140 self-test failed on <path>: <cause>
```

**Match:** `fips140 self-test failed on`

**Cause.** With `GODEBUG=fips140=only`, the server first runs each encryption path it uses
once with a throwaway key: DEK wrap/unwrap, secret encrypt/decrypt, PBKDF2 KEK derivation,
and the evidence-signing, audit-checkpoint and backup-manifest keys with an HMAC under each.
`<path>` names the one that failed and `<cause>` says why; a refusal by the Go FIPS module
reads `panic: crypto/...: ... is not allowed in FIPS 140-only mode`. This runs before any
key file is read, so nothing on disk was touched. Outside that mode the self-test does not
run, and the log says `fips140 enforced: no (self-test not run)`.
**Fix.** Not a configuration problem: this build cannot run that path in FIPS 140-only
mode. Run without `GODEBUG=fips140=only`, or use a build where the line logged at start is
`fips140 enforced: yes, self-test passed (N paths)`, and report the message as a bug.
**In place:** yes (nothing was started).

### Weak SCIM token

Real output (`scim.enabled: true`, `KEYORIX_SCIM_TOKEN=changeme-changeme-ch`, fresh install):

```
scim: SCIM token is too weak: it has only 8 distinct bytes (at least 10 are required) -- set KEYORIX_SCIM_TOKEN (or scim.token) to a generated value, for example the output of "openssl rand -base64 32", and give the same value to your IdP's SCIM connector
```

**Match:** `SCIM token is too weak`

The part after `too weak:` says which check failed (from code; the token itself is never
printed, and for a reused secret only the other secret's name is):

| Match | What it means |
|---|---|
| `it is one byte repeated` | the token is one character over and over |
| `distinct bytes (at least` | fewer than 10 different characters |
| `it contains a known placeholder` | `changeme`, `password`, `example`, `secret`, `keyorix`, `replace` ... anywhere in it |
| `it is a sample value made of placeholder words` | its letters are only words like `test`, `token`, `scim`, `your`, `here` (`test-token-1234...`) |
| `so whoever holds one holds both` | it is the same value as another configured secret (the message names it: `KEYORIX_DB_PASSWORD`, a metrics token, an SSO client secret ...) |
| `SCIM token is too short` | under 20 characters (`scim: SCIM token is too short (...)`); always refused |

**Cause.** The SCIM token is chosen by you, not generated by Keyorix, and it lets the
holder create, change and suspend users. Since #3397 a token that is obviously not random
is refused, not only one under 20 characters. **Fix.** Generate one
(`openssl rand -base64 32`), set it in `KEYORIX_SCIM_TOKEN` (or `KEYORIX_SCIM_TOKEN_FILE`)
**and** in your IdP's SCIM connector, restart. Avoid short hex tokens: a 20-character
`openssl rand -hex 10` value has fewer than 10 distinct characters about one time in
twenty. **In place:** yes (update the IdP at the same time, or provisioning fails until
you do).

**Upgrade grace (ADR-112).** On a deployment that already has users and has not yet
started once with a passing token, the same text is printed as a
`WARNING: ... ADR-112 grace period: ...` line and the server starts. The first start with
a token that passes (or with SCIM off: the grace is for a token already in use, not one
added later) ends the grace period for good (system metadata
`adr112.scim_token_strength.enforced`); a fresh install refuses from its first start. A
token under 20 characters (`SCIM token is too short`) is always refused, grace or not.

### Binary built without a connector or rotation backend — from code

```
connect: connector "<name>" has type "<type>", which this server binary was not built with (excluded by the no<provider> build tag) — rebuild without -tags no<provider>, or remove this connector
```

**Match:** `which this server binary was not built with`

**Cause.** A minimal build (for example `-tags nogcp`) with a config that uses that
provider. **Fix.** Use the full build, or remove the connector/rotation backend.
**In place:** yes.

---

## HA and multiple replicas

### `single_writer` on SQLite

Real output:

```
Configuration is invalid: storage.database.single_writer is only supported with storage.type postgres: it relies on PostgreSQL session advisory locks and triggers; remove the setting
```

**Match:** `storage.database.single_writer is only supported with storage.type postgres`

**Fix.** Remove the setting, or move to PostgreSQL. **In place:** yes.
[single-writer.md](../single-writer.md).

### `single_writer` with a transaction pooler

Real output:

```
Configuration is invalid: storage.database.single_writer is not supported with storage.database.pooler pgbouncer-transaction: its holder lock and session tag are session-scoped; use pgbouncer-session or connect directly
```

**Match:** `is not supported with storage.database.pooler pgbouncer-transaction`

**Fix.** Point `single_writer` at a session-mode pooler or the database directly.
**In place:** yes. [postgresql-poolers.md](../postgresql-poolers.md).

### `pooler` on SQLite

Real output:

```
Configuration is invalid: storage.database.pooler "pgbouncer-session" applies only to storage.type postgres; remove it
```

**Match:** `applies only to storage.type postgres; remove it`

**Fix.** Remove `pooler` (and `native_read_pool_max`, which has the same rule). **In place:** yes.

### `audit_durability: standard` on SQLite

Real output:

```
Configuration is invalid: storage.database.audit_durability: standard is only supported with PostgreSQL; SQLite runs strict only -- remove the setting or set it to strict
```

**Match:** `standard is only supported with PostgreSQL`

**Fix.** Remove the setting or use `strict`. **In place:** yes.
[UPGRADING.md §6c](../UPGRADING.md#6c-postgresql-audit-durability-now-defaults-to-standard).

### Undeclared transaction-mode pooler — from code

```
storage.database: two open connections were served by the same PostgreSQL backend (pid <n>), so a transaction-mode connection pooler (for example PgBouncer pool_mode=transaction) is between Keyorix and PostgreSQL. Session advisory locks and cached prepared statements are not safe there. Set storage.database.pooler: pgbouncer-transaction (docs/postgresql-poolers.md), or run the pooler in session mode
```

**Match:** `a transaction-mode connection pooler`

**Cause.** The start-up probe found a pooler you did not declare. **Fix.** Declare
`storage.database.pooler: pgbouncer-transaction`, or switch the pooler to session mode.
**In place:** yes (before the server is up). [postgresql-poolers.md](../postgresql-poolers.md).

### `single_writer` and more than one replica — from code

| Match | What it means |
|---|---|
| `storage.database.single_writer allows exactly one server, but` | `security.auth_rate_limit_fallback.replicas` declares more than one |
| `another Keyorix server holds the single-writer lock` | a second server started against the same database; stop it |
| `other Keyorix server(s) are attached to this database` | same, discovered when the first one starts |
| `holds this database (backend pid` | a *non*-single-writer server started against a database a single-writer server holds; stop one of them |
| `PostgreSQL 13 or later is required` | `single_writer` needs PostgreSQL 13+ |
| `fence verification failed` | the write-fence triggers are not all present |
| `has an unexpected definition` | a fence trigger was altered; the message gives the `DROP TRIGGER` to run, then restart |
| `a fenced table has a child or a parent table` | table inheritance bypasses the fence; remove it |
| `never runs without its write fence` | the fence could not be installed; fix the cause shown before it |

**In place:** stop first for the lock messages (one writer at a time is the point);
the fence ones need a DBA's care: [single-writer.md](../single-writer.md).

### An admin operation is running — from code

```
an admin operation is running against this database; retry when it finishes
```

**Match:** `an admin operation is running against this database`

**Cause.** A server start collided with a running `admin` command (backup, restore,
rotation). **Fix.** Wait for the command to finish, then start. **In place:** yes.

### The SQLite server lock file cannot be locked or watched — from code

```
lock server lock file "<datadir>/keyorix.db.server.lock": operation not supported: the filesystem holding it does not support file locks (flock), so a server and an admin command cannot exclude each other; put the SQLite database on a local filesystem, or use storage.type: postgres
```

**Match:** `the filesystem holding it does not support file locks`
`the filesystem reports no inode numbers`
`between opening and locking it`

**Cause.** The SQLite database (and its `.server.lock` beside it) is on a filesystem
without `flock` support or without inode numbers (some network and FUSE mounts), or a
process keeps deleting or replacing `.server.lock`. The server and every `admin` command
refuse rather than run without the server/admin exclusion. **Fix.** Move the database to a
local filesystem, or use PostgreSQL; never delete `.server.lock`
([j7-troubleshooting.md](j7-troubleshooting.md#an-admin-command-while-the-server-is-still-running)).
**In place:** no.

---

## Admin commands

### An admin command while the server is running

Real output (server running on the same SQLite database, `admin backup`):

```
Error: on SQLite, admin backup needs the database to itself -- stop the server first (a live backup without downtime needs Postgres): a Keyorix server (or another admin command) appears to be using this database (another process holds this database (a live server, or another admin command) via <datadir>/keyorix.db.server.lock) — admin commands must not run concurrently with either; stop it first, or pass --force if you are certain this is safe.
Run admin commands with the server stopped: stop the server (for example 'systemctl stop keyorix'), run this command again, then start the server.
```

Inside a container (Compose) the last lines name the Compose sequence instead (from code, not
run here: the capture host is not a container):

```
With Docker Compose, run admin commands in a throwaway container while the server is stopped:
  docker compose stop backend
  docker compose run --rm backend ./keyorix-server admin <command>
  docker compose start backend
```

**Match:** `appears to be using this database`

**Cause / fix.** Stop the server, or run the command in a throwaway container as shown.
`--force` skips the check, and is only right if you know nothing else is writing. With
`single_writer`, `--force` is refused outright (`--force cannot override it`, from code).
**In place:** stop first. [j7](j7-troubleshooting.md#an-admin-command-while-the-server-is-still-running).

### An admin command cannot open the server lock file — from code

```
Error: cannot open the server lock file: <datadir>/keyorix.db.server.lock: permission denied — admin commands must not run concurrently with a server, and this file is how they tell; make it readable and writable by the user running this command (the same user the server runs as), or pass --force if you are certain no server is running
```

**Match:** `cannot open the server lock file: `

**Cause.** On SQLite, the `.server.lock` beside the database cannot be created, opened or
locked by the user running the `admin` command: most often it belongs to the server's
account and the command runs as another user (for example root, or a different container
user), or the directory is read-only. Nothing was learned about a running server, so the
command refuses. Before this wording the same refusal said `cannot connect to the database`.
**Fix.** Run the command as the server's user, or fix the file's owner and mode (0600, owned
by the server's user). Do not delete `.server.lock` while a server runs. `--force` skips the
check and is only right if you know no server is running. **In place:** yes, once the
permissions are fixed.

### Backup output already exists

Real output:

```
Error: --output "b1.kxb" already exists -- each backup is a distinct artifact, pick a new path (e.g. include a timestamp)
```

**Match:** `each backup is a distinct artifact`

**Fix.** Pick a new file name. Nothing was overwritten. **In place:** yes.

### Restore over a non-empty destination

Real output:

```
Error: database "<datadir>/keyorix.db" already exists and is not empty -- restore refuses to overwrite it (pass --overwrite-existing if you are certain, e.g. this is a genuine disaster-recovery restore; the normal flow is restoring into a fresh/empty data dir)
```

**Match:** `restore refuses to overwrite it`

**Cause.** Restore will not replace a live database. **Fix.** Restore into an empty data
directory and switch over, or `--overwrite-existing` for a disaster recovery (and read the
rollback entry above: it may follow). The same message exists for a non-empty PostgreSQL
target. **In place:** no. [drill-backup-restore.md](drill-backup-restore.md).

### Other restore and backup refusals — from code

| Match | What it means |
|---|---|
| `restore refuses to mix formats` | the archive format differs from what this binary expects; use the release that wrote it |
| `restore refuses to mix backends` | an SQLite archive into PostgreSQL, or the reverse; see [SELF_HOSTING.md "Moving from SQLite to Postgres"](../SELF_HOSTING.md#moving-from-sqlite-to-postgres) |
| `changed during the backup` | a key file changed while the backup ran (rotation in progress); nothing was written, retry |
| `could not read the rollback-protection witness file` | the host's witness file is unreadable or corrupt; investigate before restoring, it is not treated as absent |
| `restore refuses a partial/mismatched key-file set` | the archive holds a different number of key files than this config's encryption settings expect; restore with the config the backup was taken with |
| `restore refuses a mismatched key-file set` | a key file in the archive is for another path than this config's `dek_path`/`salt_path` |
| `backup archive's manifest signature is invalid` | the archive is corrupted or was altered; use another copy |
| `restore refuses unlisted entries` | the archive contains a file its own manifest does not list; do not use it |
| `restore refuses non-regular entries` | the archive contains a link or device entry; do not use it |
| `refusing to generate a TLS certificate` | `admin init --secure-files` found the system clock implausible (a device with no RTC and no NTP reads a date long before this build); a certificate made now would expire when the clock is corrected. Set the clock, or place your own certificate and key at the paths the message names |
| `already exists -- refusing to overwrite` | the `--output` file of `admin recovery-key rotate` already exists; choose another path or remove the old file deliberately |
| `could not be checked because the config file failed to load` | `admin verify-audit` without `--anchor` could not read the config to see whether `audit.offline_anchor_path` is set, so it will not silently verify without it; pass `--anchor` or fix the config load error shown after it |

### Interrupted restore: recovery refuses

`admin restore --recover` finishes or undoes a restore that stopped between staging and
completion (see [Interrupted restore](#interrupted-restore--from-code) and
[restore-failure-modes.md](restore-failure-modes.md), which owns the procedure). It checks
the journal before it renames anything, and refuses when it cannot vouch for what the journal
says. Each refusal changes nothing, keeps the journal, and so keeps the server refusing to
start.

How the blocks below were made: a restore cannot be stopped at that step from the command
line, so the journal was written by hand (JSON, in the format `internal/restorejournal`
reads) beside a staged copy of `keys/dek.key` on a SQLite install, and then altered one way
per block. The text is printed by the real `keyorix-server admin restore --recover`;
the state it reacts to is a reproduction of what a killed restore leaves, not a killed
restore. Absolute paths are shown as `<datadir>`.

A staged file whose content is not what the restore staged (real output; the staged copy
overwritten with other bytes):

```
Found the journal of an interrupted restore (sqlite backend, started 20261030T184100): <datadir>/.keyorix-restore-journal.json
Error: staged file "<datadir>/keys/dek.key.restoring-abc123" does not have the content the restore staged for "<datadir>/keys/dek.key" (SHA-256 bbc9c50e35b796df9a30bc9734819e2386ba83321a887f9d0c48e59dec3ba185, journal records b9ff44ba74f02a231f9a0e8a30f33b9fb2a3d3d225db1e48f935e2c1b8759a4e): recovery refuses to install it -- recovery refuses to roll forward and changed nothing; the journal <datadir>/.keyorix-restore-journal.json is kept and the server keeps refusing to start. See docs/operator/restore-failure-modes.md ("Recovery refuses")
```

A staged file that is gone while the live file is not the restored one reads
`staged file "..." is missing and "..." is not the restored file (a crash lost the staged copy before it was installed): recovery refuses to install it -- ...` (from code, same ending).

A journal that names a file which is not one of this config's key files or database (real
output; the entry's `path` changed to `certs/server.key`):

```
Found the journal of an interrupted restore (sqlite backend, started 20261030T184100): <datadir>/.keyorix-restore-journal.json
Error: restore journal names "<datadir>/certs/server.key", which is not one of this config's key files or database (relative paths resolve against the working directory: run --recover from the directory the restore ran in) -- recovery refuses to act on it; inspect the journal
```

A journal that does not parse (real output; the file cut off after the opening of `entries`):

```
Error: restore journal "<datadir>/.keyorix-restore-journal.json" does not parse: unexpected end of JSON input -- recovery refuses to guess; inspect the file
```

An install that fails after the data is committed, here because a key file already exists
beside a journal written for a restore without `--overwrite-existing` (real output):

```
Found the journal of an interrupted restore (sqlite backend, started 20261030T184100): <datadir>/.keyorix-restore-journal.json
Error: install "<datadir>/keys/dek.key": "<datadir>/keys/dek.key" was created concurrently during restore and is not empty -- refusing to overwrite it -- the restored data is committed but not every key file is installed; the journal <datadir>/.keyorix-restore-journal.json is kept and the server refuses to start until `keyorix-server admin restore --recover` completes the restore
```

**Match:** `recovery refuses to roll forward and changed nothing`, `recovery refuses to install it`, `recovery refuses to act on it`, `recovery refuses to guess`, `the restored data is committed but not every key file is installed`, `was created concurrently during restore and is not empty -- refusing to overwrite it`

The same family, not run (each needs a failure or a race that the command line cannot
produce on demand):

| Match | What it means |
|---|---|
| `the restore is complete, but its journal could not be removed` | the restore finished and only deleting the journal failed (the error in parentheses says why). The server refuses to start while the journal exists; run `keyorix-server admin restore --recover`, which finishes the remaining steps (it writes the restore's audit events a second time, see [restore-failure-modes.md](restore-failure-modes.md#the-order)) and removes it |
| `the restored data is committed, but encrypting the notification channel URLs it carried failed` | an older archive carried plaintext notification-channel URLs and encrypting them failed (the error in parentheses says why). The journal is kept so `--recover` runs that step again; fix the cause, then run `--recover` |
| `was created concurrently during restore -- refusing to overwrite it` | a file appeared at a key-file path between the check and the install (the empty-file form of the message above); nothing was overwritten. Find what created it, then run `--recover` or restore again |
| `still has a non-empty WAL after closing` | committed pages of the staged SQLite database still sit in its `-wal` file, which the install does not carry over, so the restore stops before installing it; the live database and key files were not touched. Re-run the restore |

**Cause.** The journal lists the files a restore had staged and the content hash of each.
Recovery refuses to rename a staged file over a live key file when the staged file is gone or
changed (a directory entry lost to power loss, a hand-edited file, a planted one), when the
journal points outside this config's key files and database, or when it cannot be read at all:
rolling forward would pair the restored data with key files from another point in time, which
makes secrets unreadable or encrypts new ones under the wrong key, and recovery never guesses.
An install that fails after the data was committed (a file in the way, a read-only directory,
a full disk) stops with the journal kept so the same command can be run again.
**Fix.** Stop every server on this data. Read the named file and the journal; do **not** delete
the journal and start the server on the files as they are. For an unvouched staged file, keep
the journal and every `*.restoring-*` and `*.pre-restore-*` file for inspection (move them out
of the data directory), then restore the archive again with `--overwrite-existing`. For an
install failure, remove its cause and run `admin restore --recover` again with the same config
and working directory. **In place:** no, stop first.
[restore-failure-modes.md](restore-failure-modes.md#recovery-refuses-a-staged-file-it-cannot-vouch-for),
[`--recover`](restore-failure-modes.md#admin-restore---recover),
[where the journal is](restore-failure-modes.md#where-the-journal-is-and-who-checks-it).

### Restore: backup older than an accepted audit loss

Real output (an `admin backup` taken before the loss, then `admin restore --input old.kxb
--overwrite-existing`; the host's witness file was written by hand to the layout an accepted
loss leaves, one seal, because running a real `admin audit accept-loss` needs a broken chain):

```
Error: refusing to restore: this backup was taken before audit loss acceptance #1 recorded on this host (the archive's audit trail is under 0 seal(s), this host's under 1) -- restoring it would bring back the state that acceptance replaced and un-revoke access revoked since. Pass --allow-rollback if this is a genuine disaster-recovery restore of an intentionally older backup
```

**Match:** `this backup was taken before audit loss acceptance`

**Cause.** `admin audit accept-loss` seals a chain break and the host remembers the number of
seals it has accepted. An archive written under fewer seals predates that acceptance: restoring
it would bring back the state the acceptance replaced, including access revoked since, so it is
refused like the older-than-this-host case above. It is refused whatever the event counts say,
because an accepted loss lowers the count. **Fix.** Restore a backup taken after the
acceptance. For a real disaster recovery onto this host, `--allow-rollback` records the
override in the audit trail; re-check who has access afterwards. **In place:** no.
[audit-chain-break-runbook.md](audit-chain-break-runbook.md#7-containment-and-the-re-anchor-question),
[drill-backup-restore.md](drill-backup-restore.md).

### Restore: manifest high-water value does not parse — from code

```
backup archive's manifest carries an audit high-water value that does not parse -- the manifest may be corrupted or tampered with; restore refuses rather than treat this as if the archive had no recorded history
```

**Match:** `carries an audit high-water value that does not parse`

Not run: the archive's manifest is signed, so an altered value normally fails the signature
check first; this message was not reached with a real archive.
**Cause.** The rollback-protection value in the archive manifest is present but unreadable.
**Fix.** Use another copy of the archive or an earlier backup; do not edit the manifest. The
restore stopped before it wrote anything. **In place:** yes (nothing was changed).
[drill-backup-restore.md](drill-backup-restore.md).

### `accept-loss` while a server or another admin command runs

Real output (a server running on the SQLite database, `admin audit accept-loss --force ...`):

```
WARNING: could not acquire this database's exclusive lock (another process holds this database (a live server, or another admin command) via <datadir>/keyorix.db.server.lock) — proceeding anyway because --force was given. A live server or another admin command may be concurrently using this database; this command is not protected against that race.
Error: accept-loss runs only under the exclusive database lock (stop the server and every other admin command); --force is refused: another process holds this database (a live server, or another admin command) via <datadir>/keyorix.db.server.lock
```

**Match:** `accept-loss runs only under the exclusive database lock`

**Cause.** Sealing an audit loss writes the seal record, an audit event, a new checkpoint and
the high-water mark, which must not race another writer. Unlike other admin commands,
`accept-loss` does not let `--force` past the lock; the WARNING line above is the shared lock
step, and the refusal follows it. **Fix.** Stop the server and every other admin command on this database
(every replica, on every host), then run it again without `--force`. It prints what it would
accept and writes nothing without `--confirm`. **In place:** stop first.
[audit-chain-break-runbook.md](audit-chain-break-runbook.md#7-containment-and-the-re-anchor-question).

### Rotation commands — from code

| Match | What it means |
|---|---|
| `Re-run with --confirm` | rotation changes keys/rewraps data and is not run without `--confirm` (dry-run first for the DEK) |
| `stop the running server before rotating` | the key lock is held; stop the server |
| `stop the running server before running it` | the key lock is held (`rotate`, `upgrade-aad`, `rotate-kek`, `migrate-provider` and the authentication-data commands print `refusing to <command>:` first); stop the server or wait for the other key command |
| `must run on the server host` | the config says `storage.type: remote`; run on the server's host |

Real output of the `stop the running server before running it` row (SQLite, a server running
on the data directory, `admin encryption rotate --confirm --force`; `--force` only gets past
the first lock, the WARNING line, never the key lock):

```
WARNING: could not acquire this database's exclusive lock (another process holds this database (a live server, or another admin command) via <datadir>/keyorix.db.server.lock) — proceeding anyway because --force was given. A live server or another admin command may be concurrently using this database; this command is not protected against that race.
⚠️  Rotating DEK and re-encrypting all DEK-encrypted rows. This holds a write lock on the database — stop write traffic before continuing.
Error: refusing to rotate: another process already holds the DEK lock (a live server, or a concurrent rotation): resource temporarily unavailable — stop the running server before running it
```

**In place:** stop first. [j6-key-rotation.md](j6-key-rotation.md). With several replicas on PostgreSQL,
[DEK rotation refused under `--force`](#dek-rotation-refused-under---force).

---

## What this page does not cover

- The full list of every refusal found, how it was built and what the search could not see:
  [startup-refusals-inventory.md](startup-refusals-inventory.md). A test logs the refusals in
  the code that this page does not mention yet; that log is not a failure, because
  messages built at run time from variables cannot be found by reading source.
- Container- and Helm-level failures (a pod that crash-loops before `keyorix-server` runs,
  entrypoint secret-file checks) — see [j8-kubernetes.md](j8-kubernetes.md).
- Warnings (the server runs): the `WARNING:` lines. They are listed in the
  [hardening guide](../security/hardening-guide.md).
