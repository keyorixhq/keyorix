# Keyorix — Quick Start

A secrets manager you can run on one machine, in an air-gapped network, or for a
team. This page gets you from a clone to a stored secret. Every command below is
checked against the CLI's own flag definitions by
`internal/cli/quickstart_commands_test.go`.

## Build

```bash
make build
```

Produces `./bin/keyorix` (CLI) and `./bin/keyorix-server` (API server).
Go 1.23+ and a C toolchain for SQLite are the only requirements.

## Initialise

`system init` writes a config file and generates the encryption keys. Run it
once, before anything else.

```bash
export KEYORIX_MASTER_PASSWORD='choose-a-strong-passphrase'
./bin/keyorix system init --config ./keyorix.yaml
```

`KEYORIX_MASTER_PASSWORD` is not optional. With the default passphrase provider
the key-encryption key is derived from it plus the on-disk salt, so the CLI and
the server both refuse to start without it. Set it in your shell profile, a
systemd unit, or a secrets file your init system reads — anywhere but a
committed file.

Keep `keys/` and the database file together and back them up together. Losing
`keys/kek.salt` means losing every secret in the database; there is no recovery
path, by design.

## Use it — CLI only

The CLI defaults to **embedded mode**: it opens the local database directly and
needs no server running. For one machine or an air-gapped box, this is the whole
product.

```bash
./bin/keyorix secret create --name "stripe-api-key" --value "sk_test_..."
./bin/keyorix secret create --name "deploy-key" --from-file ~/.ssh/id_ed25519
./bin/keyorix secret list
./bin/keyorix secret get --id 1
```

Secrets live in a project and an environment, both defaulting to `1`:

```bash
./bin/keyorix secret create --name "db-password" --value "..." \
  --project 2 --environment 3 --description "primary read-write user"

# Or address one by reference instead of ID
./bin/keyorix secret get --ref myproject/production/db-password
```

Useful on create: `--max-reads N` (burn after N reads), `--expires` (RFC3339),
`--folder ID`, `--type`.

## Use it — server and dashboard

Start the server when you want the HTTP API, the web dashboard, or more than one
person:

```bash
KEYORIX_CONFIG_PATH=./keyorix.yaml ./bin/keyorix-server
```

- Health: <http://localhost:8080/health>
- OpenAPI spec: <http://localhost:8080/openapi.yaml>
- Swagger UI: <http://localhost:8080/swagger/> — only when `server.http.swagger_enabled: true`

TLS is off in the generated config. Turn it on, or front the server with a
TLS-terminating proxy, before anything reaches a network you do not control.
`security.require_transport_tls` makes that failure loud instead of silent.

For Postgres instead of SQLite, `docker compose up -d postgres` starts one, and
`configs/dev.yaml` shows the connection block.

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
`rotation`, `machine` (machine identities for CI), and `encryption` (key
rotation).

- **Configuration reference:** [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
- **Deployment:** [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md), and
  `server/config/production.yaml` as a starting config
- **API:** [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)
- **Security model:** [`docs/SECURITY.md`](docs/SECURITY.md)

The CLI speaks five languages (de, en, es, fr, ru); set `locale.language`.

## Status, honestly

The HTTP API and the CLI's default embedded mode are the complete, supported
paths. Two things are not finished, and are labelled where you would hit them:

- **`storage.type: remote`** (CLI pointed at a central server) is work in
  progress — see [`docs/REMOTE_CLI_SETUP.md`](docs/REMOTE_CLI_SETUP.md) for what
  works today.
- **gRPC** is a partial data-plane surface, off by default — see
  [`docs/adr-104-grpc-scope-and-parity.md`](docs/adr-104-grpc-scope-and-parity.md).

If something here does not work as written, that is a bug in this page and worth
an issue — the commands are meant to be copy-pasteable.
