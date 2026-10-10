# Keyorix — Quick Start

A secrets manager you can run on one machine, in an air-gapped network, or for a
team. This page gets you from a clone to a stored secret. Every `keyorix ...`
command below is checked against the CLI's own flag definitions by
`cli/cmd/quickstart_commands_test.go`; every `keyorix-server admin ...` command is
checked the same way by `server/admin/quickstart_commands_test.go`.

## Build

```bash
make build
```

Produces `./bin/keyorix` (CLI) and `./bin/keyorix-server` (API server).
Go 1.23+ and a C toolchain for SQLite are the only requirements.

`make build` does **not** include the web UI: the server then logs
`Web UI not bundled in this build; serving API only` and shows a placeholder page
at `/`. To get the UI, build it first (needs Node and `pnpm`) and then build
again:

```bash
make build-ui
make build
```

Everything below works with the CLI alone. The Docker demo (`scripts/demo/up.sh`)
already bundles the UI.

## Initialise the server host

`keyorix-server admin init` writes a config file, and creates the encryption key
directories and an empty database file, on THIS host. Run it once, before
starting the server:

```bash
export KEYORIX_MASTER_PASSWORD='choose-a-strong-passphrase'
./bin/keyorix-server admin init --config ./keyorix.yaml
./bin/keyorix-server admin encryption init --config ./keyorix.yaml
./bin/keyorix-server admin migrate --config ./keyorix.yaml
```

`admin init` only creates the encryption key *directories* — it does not generate
key material. `admin encryption init` generates the actual KEK/DEK pair; the
server refuses to start without it.

`KEYORIX_MASTER_PASSWORD` is not optional. With the default passphrase provider
the key-encryption key is derived from it plus the on-disk salt, so the server
refuses to start without it. Set it in your shell profile, a systemd unit, or a
secrets file your init system reads — anywhere but a committed file.

Keep `keys/` and the database file together and back them up together. Losing
`keys/kek.salt` means losing every secret in the database; there is no recovery
path, by design.

### Generate the admin recovery key

If every admin account is ever locked out (lost password, lost MFA device), the
only way back in is `keyorix-server admin recover-admin` on this host — and by
default it also requires an admin recovery key. No key exists until you
generate one, so do it now, while the server is not running yet:

```bash
./bin/keyorix-server admin recovery-key rotate --config ./keyorix.yaml
```

It prints a 256-bit key **exactly once**. Store it offline and away from this
host (a password manager, a sealed envelope) — not next to the database or
`keys/`. Only a one-way verifier is stored server-side, so a lost key cannot be
recovered: run the command again to replace it (the old key stops working
immediately). It needs the database to itself and refuses while the server is
running — to rotate the key later, stop the server, run it, then start the
server again. `--recipient <age1...>`
prints it age-encrypted instead of in plaintext; see
`docs/design-b2-recover-admin.md` for the design.

## Start the server and bootstrap the admin account

The CLI is REST-only — it always talks to a running `keyorix-server` over the
network, even on a single machine. Start the server, then bootstrap the first
admin account and default workspace with `keyorix system init --server`:

```bash
export KEYORIX_BOOTSTRAP_TOKEN='choose-a-bootstrap-token'
KEYORIX_CONFIG_PATH=./keyorix.yaml ./bin/keyorix-server &

./bin/keyorix system init --server http://localhost:8080 \
  --admin-username admin --admin-email admin@keyorix.local \
  --admin-password 'Correct-Horse-Battery9' \
  --bootstrap-token "$KEYORIX_BOOTSTRAP_TOKEN"
```

Two things about this command are not obvious from `--help` alone:

- **Pass `--admin-email` explicitly.** The flag's own default (`admin@localhost`)
  fails the server's email validation (no dot after `@`), so omitting it makes
  bootstrap fail with a confusing `Validation error: Validation error: Email`.
- **Pick a password with an uppercase letter, a digit, and that does not contain
  the username.** `Correct-Horse-Battery9` above satisfies all three.

`system init --server` is safe to run more than once — it is idempotent, and
reports `already_initialized` on every call after the first. It creates the
admin user, default RBAC roles, and a default workspace (a project with three
seeded environments — development, staging, production — as IDs 1/2/3) in one
call. Without `KEYORIX_BOOTSTRAP_TOKEN` set before the server starts, the server
generates and logs a random token instead — pass that one to `--bootstrap-token`.

- Health: <http://localhost:8080/health>
- OpenAPI spec: <http://localhost:8080/openapi.yaml> — only when
  `server.http.swagger_enabled: true` in `keyorix.yaml` (otherwise it returns 404)
- Swagger UI: <http://localhost:8080/swagger/> — same setting

TLS is off in the generated config. Turn it on, or front the server with a
TLS-terminating proxy, before anything reaches a network you do not control.
`security.require_transport_tls` makes that failure loud instead of silent.

What you will see on first start, and what it means:

- **Three `WARNING` lines about cleartext transport and `trusted_proxies`.**
  Expected with the generated config: TLS is off and no reverse proxy is
  trusted. Fine on one machine; act on them before exposing the server.
- **`Automatic file-permission fixing is on (security.auto_fix_file_permissions ...)`.**
  Informational. The generated config turns the setting on, so it is printed on
  every start. A permission change is reported separately as `[FIXED] <path>`; if
  there is no such line, nothing was changed. Set the option to `false` in
  `keyorix.yaml` to silence it.
- **`storage: opening existing SQLite database ...` several times** from every
  `admin` command. Harmless, including after a brand-new `admin init`.

For Postgres instead of SQLite, `docker compose up -d postgres` starts one, and
`configs/dev.yaml` shows the connection block.

## Log in

```bash
./bin/keyorix login --server http://localhost:8080 \
  --username admin --password 'Correct-Horse-Battery9'
```

Stores the session token (and server URL) at the CLI's one credential-file
location — see `keyorix status --help`. Every command below reads it from there;
none of them take `--server` again.

If the account has an authenticator app enrolled (TOTP MFA), `login` asks for a
code after the password — or pass one non-interactively:

```bash
./bin/keyorix login --server http://localhost:8080 \
  --username admin --password 'Correct-Horse-Battery9' --mfa-code 123456
```

An unused recovery code works there too. Either is used for that one request:
only the session token is stored. An account whose only second factor is a
WebAuthn passkey cannot complete a CLI login — sign in with the web UI and use a
personal access token (`KEYORIX_TOKEN`) for CLI work instead.

## Use it

Secrets live in a project and an environment. `system init --server` already
seeded project `1` with environments `1`/`2`/`3` above, so new secrets can be
created right away:

```bash
./bin/keyorix secret create --name "stripe-api-key" --value "sk_test_..."
./bin/keyorix secret create --name "deploy-key" --from-file ~/.ssh/id_ed25519
./bin/keyorix secret list
./bin/keyorix secret get --id 1               # metadata only
./bin/keyorix secret get --id 1 --show-value  # decrypted value
```

New secrets default to project `1`, environment `1`. Create another project for
anything that needs its own environments:

```bash
./bin/keyorix project create --name "my-project"

./bin/keyorix secret create --name "db-password" --value "..." \
  --project 2 --environment 3 --description "primary read-write user"

# Or address one by reference instead of ID
./bin/keyorix secret get --ref myproject/production/db-password
```

Useful on create: `--max-reads N` (burn after N reads), `--expires` (RFC3339),
`--type`, `--description`, `--interactive` (hidden-prompt value instead of
`--value` on the command line).

Export everything in a project/environment at once — the same call the
[GitHub Action](integrations/github-action/README.md) makes:

```bash
./bin/keyorix secret export --project 1 --env 1 --format json
```

## Sharing

Shares are granted to a **user or group ID**, not an email address. Before you
can share anything, both you (the owner) and the recipient need an explicit
role in the project the secret lives in — holding the global `admin` role from
bootstrap is not enough:

```bash
./bin/keyorix rbac assign-role --user admin@keyorix.local --role project_admin --project default
./bin/keyorix rbac assign-role --user alice@keyorix.local --role project_viewer --project default

./bin/keyorix user list                       # find the recipient's ID
./bin/keyorix share create --secret-id 1 --recipient-id 42 --permission read
./bin/keyorix share create --secret-id 1 --recipient-id 7 --is-group --ttl 24h
./bin/keyorix share list --secret-id 1
```

Skipping the two `rbac assign-role` lines and going straight to `share create`
fails with a bare `HTTP 403` and no explanation — this is a known rough edge,
tracked as a known gap below.

`--ttl` (a Go duration) and `--expires` (RFC3339) are mutually exclusive; either
makes the share time-bound, which is usually what you want for access granted
during an incident.

## Giving a machine (CI/app) access

```bash
./bin/keyorix machine create --name my-ci-app --project default --type ci
```

Issuing that machine a bearer token takes one more command
(`keyorix machine token issue <name>`, see
[`docs/operator/demo.md`](docs/operator/demo.md) step 5 for the full worked
example). Grant it access to a project with `machine grant-role`:

```bash
./bin/keyorix machine grant-role my-ci-app --project default --role project_viewer
```

The machine's token can now read secrets in that project with the granted
role's permissions. Revoke just the role grant (leaving the machine identity
itself intact) with `machine revoke-role`, or list what it currently holds
with `machine roles`:

```bash
./bin/keyorix machine roles my-ci-app --project default
./bin/keyorix machine revoke-role my-ci-app --project default --role project_viewer
```

See [`docs/operator/demo.md`](docs/operator/demo.md) for the full worked
example including revocation.

## Known gaps

- **Sharing requires an explicit project role on both owner and recipient**
  (see "Sharing" above) — holding the global `admin` role is not enough, and
  the failure mode (`HTTP 403`, no explanation) doesn't say so.

## What else is there

`./bin/keyorix --help` lists every command group. Beyond secrets and sharing,
the ones people reach for first are `rbac`, `project`, `user`, `group`, `audit`,
`rotation`, and `machine` (machine identities for CI). Host-side operations —
encryption key rotation, config/database maintenance — are
`keyorix-server admin --help`, not the CLI: see
[`docs/cli-migration.md`](docs/cli-migration.md) for the full old-command ->
new-command table.

- **Configuration reference:** [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
- **Deployment:** [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md), and
  `server/config/production.yaml` as a starting config
- **API:** [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)
- **Security model:** [`docs/SECURITY.md`](docs/SECURITY.md)
- **Migrating from the old CLI:** [`docs/cli-migration.md`](docs/cli-migration.md)

The CLI speaks five languages (de, en, es, fr, ru); set `locale.language`.

If something here does not work as written, that is a bug in this page and worth
an issue — the commands are meant to be copy-pasteable.
