# Migrate secrets from HashiCorp Vault (or OpenBao) to Keyorix

`keyorix-migrate` imports a Vault (or OpenBao) KV tree into Keyorix over the
public REST API. It is a separate tool and binary from the `keyorix` CLI — see
`docs/design-keyorix-migrate.md` for why. This guide walks through a typical
one-time migration of an existing, possibly orphaned Vault install.

Every run defaults to a **dry run**: it prints what it would do without
writing anything. Nothing changes until you pass `--apply`.

## 1. Get `keyorix-migrate`

```
git clone https://github.com/keyorixhq/keyorix.git
cd keyorix/migrate
make build
./bin/keyorix-migrate --help
```

**Air-gapped or Vault-only installs:** the default build also compiles in the
AWS/Azure/GCP cloud sources and their SDKs (see
`docs/migrate-from-cloud.md`'s size table). If you only need the Vault
source — the common case for an air-gapped or on-prem environment with no
cloud secret manager to migrate from — use `make migrate-vault-only`
instead, which excludes all three cloud SDKs via build tags and produces a
~10MB binary (vs. ~32MB with every source compiled in):

```
make migrate-vault-only
./bin/keyorix-migrate-vault-only --help
```

## 2. Create a least-privilege Keyorix token

`keyorix-migrate` needs a Personal Access Token (PAT) scoped to write secrets
in the one project/environment you're migrating into. Don't reuse a
broad/admin token for this — mint one specifically for the migration and
revoke it afterward:

```
keyorix pat create \
  --name "vault-migration-2026-09-25" \
  --project-id 7 --environment-id 3 \
  --scope secrets.write \
  --expires 2026-09-26T00:00:00Z    # ~24h out is usually enough for one run
```

This prints the raw token once — save it somewhere your shell history won't
keep it (see step 3). `--project-id`/`--environment-id` confine the token to
exactly the project/environment you're migrating into; `--scope secrets.write`
means it can't do anything else with your account, even if it leaked.

`keyorix-migrate` checks this token before doing anything — before even
printing the dry-run plan, and again right before `--apply` executes — and
refuses to proceed if it's revoked, expiring within the next hour, or scoped
to the wrong project/environment. If you hit that check on a real migration
run, the token's scope or expiry is the first thing to check.

**When you're done, revoke it:**

```
keyorix pat list                  # find its ID
keyorix pat revoke <id>
```

## 3. Pass credentials safely

`--token`, `--vault-token`, and `--vault-secret-id` all warn if you pass them
directly on the command line (they end up in `ps` output and your shell
history). Prefer one of:

- **Environment variables** (the default `keyorix-migrate` documents):
  ```
  export KEYORIX_TOKEN=kx_pat_...
  export VAULT_TOKEN=hvs....
  ```
- **A file**, or stdin, via the sibling `--*-file` flag:
  ```
  keyorix-migrate vault --token-file ./keyorix.token --vault-token-file ./vault.token ...
  # or, piping from stdin with "-":
  echo "$VAULT_TOKEN" | keyorix-migrate vault --vault-token-file - ...
  ```

## 4. Dry run

```
keyorix-migrate vault \
  --server https://keyorix.example.com \
  --project 7 --environment 3 \
  --vault-addr https://vault.example.com:8200 \
  --vault-mount secret \
  --vault-path team-a
```

This prints a plan: every Vault path found, what Keyorix secret name it maps
to, and whether it would be `create`d, `update`d, `skip`ped (already imported
and unchanged), or is a `conflict` (a secret already exists at that name that
this tool didn't create — resolve by renaming one side, or re-run with
`--force` to overwrite it). Nothing is written yet.

A Vault path whose latest version was deleted shows up as `skip`, with the
reason — not silently missing from the plan.

## 5. Apply

Once the plan looks right:

```
keyorix-migrate vault \
  --server https://keyorix.example.com \
  --project 7 --environment 3 \
  --vault-addr https://vault.example.com:8200 \
  --vault-mount secret \
  --vault-path team-a \
  --apply \
  --report ./migration-report.json
```

`--report` writes a machine-readable, one-line-per-item JSON log — useful for
auditing exactly what happened, or for scripting a check afterward. It never
contains a secret value.

**Re-running is safe.** `keyorix-migrate` identifies secrets it already
imported by a stable ID stored in each secret's metadata, not just by name —
running the same command again only touches items whose source value
actually changed. If a run gets interrupted partway through, just run it
again; already-imported items are skipped, not duplicated.

## Connecting to a Vault behind a private CA

If your Vault (common for on-prem and air-gapped deployments) is signed by an
internal CA rather than a public one:

```
--vault-cacert /path/to/internal-ca.pem
```

or, for a directory of CA certs:

```
--vault-capath /path/to/ca-certs/
```

There is no option to skip TLS verification — connecting to a private-CA
Vault always means trusting that CA explicitly, not turning verification off.

## AppRole authentication

Instead of a Vault token, you can authenticate with an
[AppRole](https://developer.hashicorp.com/vault/docs/auth/approle):

```
--vault-role-id <role-id> \
--vault-secret-id-file -   # or --vault-secret-id, with the same insecure-flag warning
```

## What gets imported

- The latest version of every KV v1 or v2 secret under `--vault-path`,
  recursively. **Older versions are not imported** (see
  `docs/design-keyorix-migrate.md`'s "All-versions" section) — the Keyorix
  secret's metadata records which Vault version and creation time it came
  from, so this is recoverable information, not a silent loss.
- A multi-field Vault secret (e.g. `{"user": "...", "pass": "..."}`) becomes
  one Keyorix secret per field, named `<path>-<field>`.
- Vault's KV v2 custom metadata is copied onto the Keyorix secret's own
  metadata, prefixed `vault.` (e.g. Vault's `owner` custom-metadata key
  becomes Keyorix's `vault.owner`).
- **Secret values are never printed, logged, or written to the JSON report**
  — only names, paths, and outcomes.

## Not yet supported

- `--all-versions` (importing every historical Vault version, not just the
  latest) — deferred, see above. The flag exists and returns a clear error
  rather than silently behaving like latest-only.

AWS Secrets Manager, Azure Key Vault, and GCP Secret Manager sources are
also supported — see `docs/migrate-from-cloud.md`.
