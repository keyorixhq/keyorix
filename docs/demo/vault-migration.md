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

## Access control: assisted, reviewed, never silent

Vault's access model (ACL policies, AppRole/Kubernetes/userpass auth methods, tokens) does
not look like Keyorix's (project/environment-scoped roles and machine identities) — there is
no 1:1 mapping, so this is never a "just works" step. What ships: `keyorix-migrate` reads
your Vault policies and auth-method roles and *proposes* a mapping. Nothing is created
without a human reviewing the proposal first.

```
keyorix-migrate vault plan-access  --output access-plan        # read-only, writes a report
# ... you read access-plan.md/.html ...
keyorix-migrate vault apply-access --plan access-plan.json \
  --credentials-out ./migrated-credentials.txt                  # creates only what you reviewed
```

| What | How |
|---|---|
| An AppRole role → a machine identity | `plan-access` proposes it; the AppRole's own `role_id`/`secret_id` is never copied — the machine identity gets a **freshly issued** Keyorix credential instead, shown once, written to `--credentials-out` |
| A Kubernetes auth role bound to one exact service account + namespace → a machine identity with an OIDC binding | Same — no stored secret, the workload's own cluster-issued token authenticates it |
| A policy path scoped to one project+environment, with ordinary read/write/delete capabilities → a Keyorix role + grant | Exact when the scope resolves cleanly; narrower (never wider) when it doesn't resolve exactly — see below |

**The governing rule, every time a mapping is approximate: narrower than Vault, never
wider.** A migrated grant is proven never to exceed what Vault actually allowed — an
automated equivalence check compares, for every migrated identity, what it can read in
Keyorix against what Vault's own API says it could read in Vault.

**What always needs a human, by design — listed in the review report, never silently
dropped or guessed at:**

| What | Why |
|---|---|
| `sudo` capabilities, `deny` rules overlapping an allow, Sentinel/EGP or templated policies | No safe Keyorix equivalent exists — migrating these automatically could only ever be a guess, and a wrong guess here means too much access, not too little |
| userpass users, and any directly-issued Vault token | Passwords aren't portable, and tokens are **never** migrated by design — re-provision via a machine identity instead |
| A Kubernetes auth role bound to a wildcard service account or namespace | A Keyorix binding names one exact workload identity; there's no cluster API this tool can use to enumerate which service accounts actually exist |
| A policy path that doesn't cleanly resolve to one of your Keyorix projects/environments | Reported with the exact path and reason — point it at the right project/environment with `--path-map`, or migrate it by hand |

## Doesn't move today — plan for this before cutover

| What | Why | What to do instead |
|---|---|---|
| Older versions of a secret (only the latest is imported) | A deliberate, scoped-down first release | The version a secret came from is recorded on the Keyorix secret, so nothing is lost track of — just not replayed |
| Non-KV Vault engines (Transit, PKI, Database, SSH, Cubbyhole, …) | Out of scope for this tool | Handle these separately — they're not secret values this tool is designed to move |
| Vault's own audit-device configuration | Keyorix has its own, separately-configured audit logging | Set up Keyorix's audit logging independently; it does not inherit Vault's audit config |

## The honest one-liner

**Your secret values move cleanly and safely. Your Vault access-control model gets an
assisted, human-reviewed proposal — some of it maps cleanly, some of it needs you to make
a call — but nothing is ever created without you reading the review report first, and
nothing migrated is ever proven to grant more than Vault did.**
