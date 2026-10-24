# Migrating secrets into Keyorix

**From a running secrets manager** (HashiCorp Vault/OpenBao, AWS Secrets
Manager, Azure Key Vault, Google Cloud Secret Manager): use `keyorix-migrate`,
a separate release binary. See [migrate-from-vault.md](migrate-from-vault.md)
and [migrate-from-cloud.md](migrate-from-cloud.md).

**From a file:** `keyorix secret import` runs against your Keyorix server, so
first connect:

```sh
export KEYORIX_SERVER=https://keyorix.your-company.internal
export KEYORIX_TOKEN=<a service or personal access token with secrets.write>
# or: keyorix login --server …   (prompts for the password; stores a session token)
```

Every import targets one project + environment and is **idempotent** by default
(`--skip-existing`, on): re-running skips secrets that already exist. Use
`--dry-run` first to preview without writing anything.

## File sources

```sh
keyorix secret import --file .env              --format dotenv --project 7 --env 3
keyorix secret import --file secrets.json      --format json   --project 7 --env 3
keyorix secret import --file vault-export.yaml --format vault  --project 7 --env 3
```

`dotenv` (KEY=VALUE), `json` (flat object), and `vault` (a Medusa/Vault YAML
export file) are supported.

## Flags

| Flag | Purpose |
|------|---------|
| `--dry-run` | Show what would be imported without creating anything |
| `--skip-existing` | Skip (don't fail on) secrets that already exist — default on |
| `--project`, `--env` | Target project and environment IDs (must already exist) |
| `--decrypt-with` | RSA private key to decrypt a `secret export --format encrypted-json` file |

Full reference: [`keyorix secret import`](cli-reference.md#keyorix-secret-import).

## Not yet supported

Values are imported; **version history, tags/metadata, and TTLs are not**.
