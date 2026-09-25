# Migrate secrets from AWS, Azure, or GCP to Keyorix

`keyorix-migrate` imports secrets from AWS Secrets Manager, Azure Key Vault,
or GCP Secret Manager into Keyorix over the public REST API — the same tool
and the same contract as `docs/migrate-from-vault.md`'s Vault source: a
dry-run plan by default, `--apply` to execute it, idempotent re-runs, and a
per-item report that never carries a secret value. Read that guide first for
the parts common to every source (getting the tool, creating a
least-privilege Keyorix token, passing credentials safely, dry run vs.
apply, resume). This guide covers what's specific to each cloud source.

## Credentials: always the provider's own default chain

None of the three cloud commands take a credential flag for the *source*
side — only `--token`/`--token-file` for Keyorix. Cloud credentials always
come from each provider's own standard chain:

| Provider | Chain |
|---|---|
| AWS | environment variables, shared credentials/config file, EC2 instance profile, or an IAM role for a service account (IRSA) |
| Azure | `DefaultAzureCredential`: environment, managed identity, workload identity, or `az login` |
| GCP | Application Default Credentials (ADC): environment, `gcloud auth application-default login`, or the workload identity |

Set up whichever of these your environment already uses before running the
tool — there's nothing to configure in `keyorix-migrate` itself.

## What gets imported

- Every secret the credential's IAM/RBAC scope can list and read, optionally
  narrowed with `--name-prefix`.
- A JSON-object secret value (e.g. `{"username":"...","password":"..."}`)
  imports as a **single** Keyorix secret (the whole JSON string) by default.
  Pass `--split-json` to import each top-level key as its own Keyorix
  secret instead, named `<secret>-<key>`.
- A binary secret value (AWS `SecretBinary`) is **skipped**, not imported —
  Keyorix secrets are strings, and there's no lossless string mapping for
  arbitrary binary data. It shows up in the plan/report as `skip`, with the
  reason.
- A secret AWS marks for deletion, or whose current version is disabled
  (Azure) or disabled/destroyed (GCP), is reported as **skip**, not
  imported and not silently dropped — matching the Vault source's soft-deleted
  KV v2 leaf behavior.
- **Secret values are never printed, logged, or written to the JSON
  report** — only names, paths, and outcomes, exactly like the Vault source.

Every imported secret's Keyorix metadata records `migrate.source`
(`aws`/`azure`/`gcp`), a stable `migrate.source-id` (used for idempotent
re-runs — see `docs/migrate-from-vault.md`'s "Re-running is safe"), and,
when the provider has one, `migrate.source-version` and
`migrate.source-created-at` for the specific version that was imported.

## Two source items resolving to the same Keyorix name

Because a source name gets sanitized (path separators, spaces, colons
collapse to `-`) and `--split-json` can turn one secret into several, it's
possible for two *different* source items to sanitize to the same target
name within a single run — e.g. a whole secret named `db-password` and
another secret's `--split-json` field also landing on `db-password`. When
that happens, `keyorix-migrate` reports the **second** occurrence as a
`conflict` rather than silently creating (or overwriting) a secret twice —
the plan explains which name collided; rename one side and re-run.

## AWS Secrets Manager

```
keyorix-migrate aws \
  --server https://keyorix.example.com --project 7 --environment 3 \
  --region us-east-1 \
  --name-prefix team-a/
```

- `--region` — the Secrets Manager region to read. When omitted, the SDK's
  own default region resolution applies (`$AWS_REGION`, the shared config
  file, etc.).
- `--name-prefix` — only import secrets whose name starts with this.

**Least-privilege IAM policy** (read-only list + get, scoped to a name
prefix):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:ListSecrets",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:*:ACCOUNT_ID:secret:team-a/*"
    }
  ]
}
```

(`ListSecrets` is an account-wide, non-resource-scoped API in AWS IAM — it
cannot be restricted to a name prefix at the policy level; `--name-prefix`
filters client-side after listing. `GetSecretValue` — the call that
actually reads secret content — *is* resource-scoped, so lock that down to
the names you're migrating.)

## Azure Key Vault

```
keyorix-migrate azure \
  --server https://keyorix.example.com --project 7 --environment 3 \
  --vault-url https://myvault.vault.azure.net/ \
  --name-prefix team-a-
```

- `--vault-url` (or `$AZURE_VAULT_URL`) — required.
- `--name-prefix` — only import secrets whose name starts with this.

**Least-privilege role**: assign the built-in **Key Vault Secrets User**
role (data-plane RBAC), scoped to the specific vault, to the identity
running `keyorix-migrate`:

```
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <principal-id> \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/myvault
```

This grants `Get`/`List` on secrets and nothing else (no create, delete, or
purge). If the vault still uses classic access policies instead of RBAC,
grant `Get` and `List` secret permissions the same way.

## GCP Secret Manager

```
keyorix-migrate gcp \
  --server https://keyorix.example.com --project 7 --environment 3 \
  --gcp-project my-gcp-project \
  --name-prefix team-a-
```

- `--gcp-project` (or `$GOOGLE_CLOUD_PROJECT`) — required.
- `--name-prefix` — only import secrets whose short name starts with this.

**Least-privilege role**: grant the built-in **Secret Manager Secret
Accessor** (`roles/secretmanager.secretAccessor`) role, which includes list
and access, at the project level:

```
gcloud projects add-iam-policy-binding my-gcp-project \
  --member="serviceAccount:migrate@my-gcp-project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

For a narrower grant, `roles/secretmanager.viewer` (list + read metadata,
no payload access) combined with `roles/secretmanager.secretAccessor`
scoped per-secret via IAM conditions covers exactly list-and-read without
any write permission.

## Binary size: cloud SDKs are opt-out, not opt-in

Each provider's SDK is large — GCP Secret Manager's client pulls in gRPC
and the broader Google API dependency tree, the biggest of the three. All
three are compiled in by default (so `keyorix-migrate` works out of the box
against any source), but each can be excluded at build time with a build
tag if you only need a subset:

```
go build -tags nomigrate_gcp -o bin/keyorix-migrate .              # drop GCP only
go build -tags nomigrate_aws,nomigrate_azure -o bin/keyorix-migrate .  # GCP only
```

Measured on this repo's `migrate` module (`go build`, no cloud sources at
all, was the pre-existing Vault-only baseline):

| Build | Binary size | `go list -deps` count |
|---|---|---|
| Vault only (baseline) | 10.0 MB | 223 |
| + AWS Secrets Manager | 14.0 MB | — |
| + Azure Key Vault | 13.2 MB | — |
| + GCP Secret Manager | 24.4 MB | — |
| All three (default) | 32.4 MB | 666 |

## Not yet supported

- `--all-versions` (importing every historical version, not just the
  latest) — deferred for every source, not just Vault; see
  `docs/design-keyorix-migrate.md`'s "All-versions import" section.
