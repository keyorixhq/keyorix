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

## Start the server and bootstrap the admin account

The CLI is REST-only — it always talks to a running `keyorix-server` over the
network, even on a single machine. Start the server, then bootstrap the first
admin account and default workspace with `keyorix system init --server`:

```bash
export KEYORIX_BOOTSTRAP_TOKEN='choose-a-bootstrap-token'
KEYORIX_CONFIG_PATH=./keyorix.yaml ./bin/keyorix-server &

./bin/keyorix system init --server http://localhost:8080 \
  --admin-username admin --admin-password 'choose-an-admin-password' \
  --bootstrap-token "$KEYORIX_BOOTSTRAP_TOKEN"
```

`system init --server` is safe to run more than once — it is idempotent, and
reports `already_initialized` on every call after the first. It creates the
admin user, default RBAC roles, and a default workspace (a project with three
seeded environments — development, staging, production — as IDs 1/2/3) in one
call. Without `KEYORIX_BOOTSTRAP_TOKEN` set before the server starts, the server
generates and logs a random token instead — pass that one to `--bootstrap-token`.

- Health: <http://localhost:8080/health>
- OpenAPI spec: <http://localhost:8080/openapi.yaml>
- Swagger UI: <http://localhost:8080/swagger/> — only when `server.http.swagger_enabled: true`

TLS is off in the generated config. Turn it on, or front the server with a
TLS-terminating proxy, before anything reaches a network you do not control.
`security.require_transport_tls` makes that failure loud instead of silent.

For Postgres instead of SQLite, `docker compose up -d postgres` starts one, and
`configs/dev.yaml` shows the connection block.

## Log in

```bash
./bin/keyorix login --server http://localhost:8080 \
  --username admin --password 'choose-an-admin-password'
```

Stores the session token (and server URL) at the CLI's one credential-file
location — see `keyorix status --help`. Every command below reads it from there;
none of them take `--server` again.

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

Shares are granted to a **user or group ID**, not an email address:

```bash
./bin/keyorix user list                       # find the recipient's ID
./bin/keyorix share create --secret-id 1 --recipient-id 42 --permission read
./bin/keyorix share create --secret-id 1 --recipient-id 7 --is-group --ttl 24h
./bin/keyorix share list --secret-id 1
```

`--ttl` (a Go duration) and `--expires` (RFC3339) are mutually exclusive; either
makes the share time-bound, which is usually what you want for access granted
during an incident.

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
