# What migrates from Vault

A straight answer, verified against a real migration run — not a sales claim. Full
methodology and evidence: `docs/specs/vault-migration-fidelity.md`.

## Moves cleanly

| What | How |
|---|---|
| Every secret value (KV v1 and KV v2), including the latest version of a value that's had many revisions | One command: `keyorix-migrate vault` |
| Deeply nested paths, unicode and spaces in paths and key names | Walked recursively, no special setup |
| A multi-field secret (e.g. `{"user": "...", "password": "..."}`) | Becomes one Keyorix secret per field |
| Large values (certificates, big JSON blobs) up to Keyorix's configured size limit | Byte-for-byte |
| Vault's own custom metadata on a secret | Carried onto the Keyorix secret's metadata |
| Re-running the migration (interrupted, or just to pick up changes) | Safe — already-imported secrets are skipped, not duplicated |

## Moves, with a visible note — never silently

| What | What you'll see |
|---|---|
| A Vault secret whose latest version was soft-deleted or destroyed | Listed in the migration report as **skipped**, with the reason — not silently missing |
| A secret value larger than Keyorix's configured limit | Reported as an error for that one item — the rest of the migration still completes |

## Doesn't move today — plan for this before cutover

| What | Why | What to do instead |
|---|---|---|
| Older versions of a secret (only the latest is imported) | A deliberate, scoped-down first release | The version a secret came from is recorded on the Keyorix secret, so nothing is lost track of — just not replayed |
| **Vault policies, AppRole/userpass/Kubernetes auth roles, and tokens** | Access control in Vault and in Keyorix are different models — there's no automatic mapping (yet) | **Plan to rebuild your access model by hand in Keyorix** (roles, machine identities, grants) as part of the migration project, not as an afterthought |
| Non-KV Vault engines (Transit, PKI, Database, SSH, Cubbyhole, …) | Out of scope for this tool | Handle these separately — they're not secret values this tool is designed to move |
| Vault's own audit-device configuration | Keyorix has its own, separately-configured audit logging | Set up Keyorix's audit logging independently; it does not inherit Vault's audit config |

## The honest one-liner

**Your secret values move cleanly and safely. Your Vault access-control model does not
move — budget time to rebuild it in Keyorix as a deliberate step of the migration, not
something you'll discover is missing after cutover.**
