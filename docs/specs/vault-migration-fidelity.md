# Vault/OpenBao → Keyorix migration fidelity spec

Status: Verified, MIG-1 — updated after running `scripts/vault-migration-testbed/` against
a real local Vault and Keyorix at seed sizes 30, 500, and 5000. Written from the current
`keyorix-migrate` implementation (`migrate/internal/vaultsource`, `migrate/internal/plan`,
`docs/design-keyorix-migrate.md`), not from aspiration — every "survives" claim below is
traceable to code read during this session AND confirmed by the harness; every "out of
scope" claim is traceable to an explicit absence (no code path reads or maps it) or an
explicit deferral already on record.

**One finding from running this harness was severe enough to fix during this session,
not just document**: `core.CreateSecret` silently dropped the `metadata` field on every
create (fixed in #2535, with a red/green-verified regression test) — before that fix,
every `vault.*` custom-metadata key and `migrate.source-id`/`migrate.source-version`
marker `keyorix-migrate` writes at creation time was discarded, which in turn broke the
tool's own documented "re-running is safe" / resume guarantee (the idempotency check reads
that same metadata back to tell "I made this" from "conflict"). See dimension 4 below and
the session report for the full writeup.

This spec exists because migration fidelity is the biggest risk in a first sale: if a
customer discovers after cutover that a secret, a version, or an access right silently did
not make it across, the deal — and the relationship — is dead. "We migrated everything" must
be a checkable claim, not an assertion. This document is the checklist; `scripts/
vault-migration-testbed/` is the mechanism that checks it.

## Scope: what this spec covers

HashiCorp Vault and OpenBao (wire-compatible) as the **source**, Keyorix as the **target**,
migrated via the documented path: `keyorix-migrate vault` (`docs/migrate-from-vault.md`) or
`keyorix secret import --source vault` (`docs/MIGRATION.md`) — both share the same
`vaultsource`/`plan` packages under the hood, so one fidelity contract covers both entry
points. "Migration fidelity" here means: everything the tool **claims** to move, moves
correctly; everything it does **not** move is documented as such, not silently dropped.

## Fidelity dimensions and their survival status

### 1. Secret values — SURVIVES (latest version only), one confirmed gap

- Every KV v1 or KV v2 leaf under the given mount/path, walked recursively
  (`vaultsource.Client.Walk`), including nested paths 6+ deep, unicode, and spaces, **confirmed
  byte-for-byte** against a seeded fixture (`org/team-a/service/payments/db primary/café
  crédentials`, fields `密码`/`user name`) — Vault path/key characters are URL-escaped per
  segment (`vaultsource.escapePath`), not blocked or mangled.
- Multi-field leaves (`{"user": "...", "pass": "..."}`) explode to one Keyorix secret per
  field, named `<path>-<field>`; a single-`value`-field leaf keeps the path name. Confirmed.
- **CONFIRMED GAP**: an empty-string field value is dropped silently by `readLeaf`
  (`val != ""` guard) — neither imported nor reported as a skip, unlike every other
  not-imported case this spec covers. Reproduced directly: a seeded `values/empty-value`
  leaf never appears in Keyorix and never appears in the migration report at all. Filed as
  a `migration-gap` issue (see session report) — low severity (an empty value is rarely a
  real secret) but still a silent, unreported loss, which is the exact failure mode this
  whole spec exists to catch.
- **CONFIRMED**: Keyorix's default secret-value size limit is 64 KiB
  (`internal/config.DefaultMaxSecretSize`, hard ceiling 1 MiB) — Vault itself has no
  comparable limit. A value just under that limit (~60KB) imports correctly, byte-for-byte.
  A value over it (~100KB, realistic for a large cert bundle or JSON blob a neglected Vault
  might hold) is reported as an `error` outcome in the migration report — **not silently
  dropped, not corrupting the rest of the run**, but also not pre-flighted or called out
  distinctly from any other per-item error. Filed as a `migration-gap` issue recommending
  `keyorix-migrate` detect and flag over-the-target's-limit values distinctly (see session
  report) — medium severity: data isn't lost silently, but an operator skimming a 5000-item
  report for "N error" could miss that a specific class of items needs the target's limit
  raised or the value split, rather than being a transient/retryable failure.
- Binary/base64, JSON-blob, and multi-line PEM values: carried as opaque strings; Vault
  doesn't distinguish them from any other string field. Multi-line PEM confirmed
  byte-for-byte including embedded newlines; JSON-blob confirmed byte-for-byte as an opaque
  string (never parsed/reformatted).

### 2. Version history — EXPLICITLY OUT OF SCOPE (documented deferral, not a gap)

Only the **current/latest** version of each KV v2 leaf is imported. `--all-versions` exists
as a flag and returns a hard, explicit error (`vaultsource.Client.Walk`) rather than silently
behaving like latest-only. This was a deliberate 2026-09-25 product decision
(`docs/design-keyorix-migrate.md`), recorded here because the fidelity report must say
"not imported, by design" for every prior version — never claim they survived.

What **is** captured even though old versions aren't imported: `metadata["migrate.source-version"]`
and `metadata["migrate.source-created-at"]` record which Vault version the imported value came
from, so a future all-versions pass could resume without re-deriving this from a Vault that may
have moved on. KV v1 has no version concept; these keys are omitted entirely for it (not
written empty).

### 3. Soft-deleted / destroyed KV v2 versions — CONFIRMED: SURVIVES AS A REPORTED SKIP

A leaf whose latest version is soft-deleted or destroyed is explicitly skipped with a reason
(`"version N was soft-deleted at <time>"` / `"version N was destroyed"`) in the plan/report —
not silently absent, not a 0-byte secret. Confirmed against two dedicated fixtures (a
soft-deleted-latest and a destroyed-latest leaf) plus a third case the harness also confirms
is handled distinctly: a leaf with **many versions where only a non-latest version is
soft-deleted** (`versioned/rotating-key`, versions 1-5, version 2 soft-deleted) still imports
its live latest version (5) normally — soft-deleting an old version does not shadow a live
newer one.

### 4. KV v2 custom_metadata, max_versions, cas_required — CONFIRMED, after a severe fix

- `custom_metadata` → copied onto the Keyorix secret's `metadata` map, prefixed `vault.`.
  **CONFIRMED FIXED, not CONFIRMED WORKING on first run**: the harness's first real run
  against this repo found `core.CreateSecret` silently dropped the entire `metadata` field on
  every create — `vault.owner`/`vault.ticket` and `keyorix-migrate`'s own
  `migrate.source-id`/`migrate.source-version` markers all vanished. Fixed in #2535 (see the
  session report); re-ran the harness after the fix and confirmed metadata now round-trips
  correctly. This was NOT a migrate-specific bug — any caller setting metadata at creation
  time was affected — but migrate's own idempotency mechanism (dimension 5 below) is what
  surfaced it, because that mechanism depends on reading the metadata back.
- `max_versions` and `cas_required` are **mount/leaf configuration**, not data — they have no
  Keyorix equivalent and are not read or reported anywhere in `keyorix-migrate`. Out of scope,
  but previously undocumented; this spec is the first place that says so explicitly.

### 5. Idempotency and resume — CONFIRMED SURVIVES (after the #2535 fix)

Re-running the same command is safe by construction (`plan.BuildPlan`'s name+source-id
lookup, no separate "resume" mode exists or is needed — see `docs/design-keyorix-migrate.md`
"Resume"). Confirmed two ways:
- **Idempotent re-run**: apply the full plan, then apply it again unchanged — the second run's
  report shows 0 `create` and 0 `update` (every item resolves to `skip`), and the Keyorix
  secret count is unchanged. Before the #2535 fix, this was broken: every item resolved to
  `conflict` instead of `skip` on the second run, because the metadata the conflict check
  reads back was never there to read.
- **Resume after a genuine interruption**: at seed sizes large enough to give a kill signal
  something to land on (verified at 500 and 5000 bulk secrets, not merely simulated), the
  harness starts `--apply` as a subprocess, kills it ~150ms in (mid-apply on the bulk batch),
  then re-runs to completion and asserts the final secret count exactly matches the source
  item count — no duplicates, nothing missing.

### 6. Never logs/prints/reports a secret value — CONFIRMED SURVIVES at scale

Verified structurally (code read), by a canary-value test already in-repo
(`internal/e2e/TestEndToEnd_CanaryValueNeverLogged`, `scripts/e2e/journeys/journey4`'s
`assertNoSecretValueLeaked`), and now re-confirmed by this harness at the full seeded
fixture's scale — including the large/binary/PEM/unicode values — at 30, 500, and 5000 bulk
secrets. No secret value appeared in migrate's stdout/stderr or its JSON report at any scale.

### 7. Audit trail of the migration itself — CONFIRMED PARTIAL, as predicted

- `--report` writes a per-item JSON log (path, target name, outcome, never a value) —
  satisfies "the migration itself is audited" in the sense of an operator-facing record.
- **CONFIRMED**: each migration-created secret DOES produce a Keyorix-side `secret.created`
  audit event (`GET /api/v1/audit/logs?secret_id=...`) — "the migration itself is audited" is
  true in that sense.
- **CONFIRMED NOT DISTINGUISHED**: that audit event's `actor_type` is plain `"user"`, identical
  to a human manually creating the same secret with the same PAT — there is no marker anywhere
  in the audit trail saying "this came from a migration tool," because `migrate` authenticates
  as an ordinary PAT and no code path adds such a distinction. An incident responder or
  compliance reviewer looking at the audit log months later cannot tell "an operator ran
  keyorix-migrate on this date" from "an operator manually created 5000 secrets one at a time
  with a script." Filed as a `migration-gap` issue (see session report) — low/medium severity
  (nothing is lost or wrong, but traceability is weaker than an operator might assume).

### 8. Policies, auth methods, tokens, audit-device config — NOT MIGRATED AT ALL

This is the headline gap, and the reason this spec calls it out before any seed script is
written: **`keyorix-migrate` has no code path that reads, maps, or mentions Vault ACL
policies, AppRole/userpass/Kubernetes auth-method roles, tokens, or audit-device
configuration as migratable objects.**

- AppRole and token credentials are used **only** to authenticate `keyorix-migrate` itself to
  Vault for the duration of one run — they are consumed, not migrated.
- `migrate/internal/healthscan` (`keyorix-migrate vault scan`) **reads** policies, auth
  methods, root tokens, and audit devices — but only to score Vault's own health/migration
  readiness (`check_policies.go`, `check_auth_methods.go`, `check_audit.go`,
  `check_root_tokens.go`). It never writes anything to Keyorix. Scanning is not migrating.
- There is consequently **no mechanism, not even a partial one, to check "the same identity
  can read the same secrets in Keyorix as it could in Vault, and nothing more."** That
  property is not a bug to fix inside `keyorix-migrate` — it would require designing how a
  Vault policy (path-glob ACL rules over a tree Keyorix doesn't organize the same way) and a
  Vault auth-method role map to a Keyorix role/machine-identity grant, which is a product
  design question (how should a Vault `path "secret/data/team-a/*" { capabilities = ["read"] }`
  policy, bound to an AppRole, become a Keyorix project/environment-scoped grant on a Keyorix
  machine identity?), not an implementation gap in an otherwise-complete feature.

**This spec treats access-control migration as explicitly out of scope for the current tool,
and recommends the gap be filed as a single high-severity `migration-gap` issue asking for a
product decision, not chased as a code fix in this session** — consistent with this repo's
"stop and ask for product decisions" practice and the session brief's own instruction that
anything in auth/authz is filed, not fixed, by this session.

### 9. Other Vault secrets engines (Transit, PKI, Database, SSH, Cubbyhole, …)

Out of scope structurally: `vaultsource.Client` only walks a KV mount. No other engine type is
read. Not a regression from anything promised — `docs/migrate-from-vault.md` and
`docs/MIGRATION.md` both describe KV only — but this spec states it explicitly so the fidelity
report has an explicit "not attempted" row instead of a silent absence.

### 10. Scale and pagination — CONFIRMED CORRECT at 5000 secrets; one harness bug found along the way

Measured directly at seed sizes 30, 500, and 5000 bulk secrets (plus the fixed fixture) under
one Vault mount. `vaultsource.Walk` has no explicit pagination (Vault's own LIST response
isn't paginated for KV metadata listing), and this was confirmed to not be a problem in
practice: all 5000 bulk secrets were found, planned, and migrated correctly — exact count
match, no duplicates, no missing items, sampled values byte-for-byte correct throughout.
Wall-clock for the full secret_mount pass (seed 5000 + dry-run + apply + idempotent re-run +
resume-after-interruption re-run, i.e. roughly three full passes over the data) was ~300s;
a single migration pass over 5000 secrets is correspondingly on the order of 1-2 minutes —
not fast (one HTTP round-trip per secret, no batching), but correct, and well within what a
one-time migration can tolerate.

**A real bug surfaced while building the harness itself, not in the product**: the first
version of this harness's own Keyorix-side secret-count check only read page 1 of
`GET /api/v1/secrets` (which paginates, default `page_size=20`, max 100 —
`server/http/handlers/secrets_list.go`'s deep-pagination-DoS guard) and so under-reported the
true count once the project held more secrets than one page. Fixed in the harness itself
(walks every page via `total_pages`) before this spec's "CONFIRMED" claims above were made —
flagged here as a caution for anyone else writing a Keyorix API consumer that lists secrets:
the list endpoint paginates, there is no "give me everything" mode.

## Fidelity report

Filled in after running `scripts/vault-migration-testbed/` against a real local Vault +
Keyorix at seed sizes 30, 500, and 5000. Full writeup: session report (SESSION-MIG-1.md).

| Dimension | Survived | Notes / issue |
|---|---|---|
| KV v1 secret values | Yes | byte-for-byte, confirmed |
| KV v2 secret values (latest version) | Yes | byte-for-byte, confirmed at 30/500/5000 secrets |
| Unicode/space paths and keys | Yes | confirmed with a 6-deep path, CJK field name, spaces |
| Nested paths (6+ deep) | Yes | confirmed |
| Multi-field leaf explosion | Yes | confirmed |
| Empty-string field values | **No — silent, unreported** | confirmed gap; filed `migration-gap`, low severity |
| Large values (near 64KiB target limit) | Yes | confirmed at ~60KB |
| Over-the-limit values (~100KB) | Reported as `error`, not silently dropped | filed `migration-gap`, medium severity (not pre-flighted/distinct) |
| Binary/base64 values | Yes | confirmed non-empty, correct length |
| JSON blob values | Yes | byte-for-byte, confirmed |
| Multi-line PEM values | Yes | byte-for-byte incl. embedded newlines, confirmed |
| KV v2 version history (beyond latest) | Out of scope (documented) | unchanged from design; `--all-versions` errors explicitly |
| Soft-deleted version, non-latest (shadowed by a live newer version) | Yes | confirmed: live v5 imports despite v2 being soft-deleted |
| Soft-deleted version, latest | Yes, as a reported skip | confirmed reason text |
| Destroyed version, latest | Yes, as a reported skip | confirmed reason text |
| `custom_metadata` | **Was No, now Yes** | found + fixed #2535 (CreateSecret dropped `metadata` entirely); confirmed working after fix |
| `max_versions`/`cas_required` config | Out of scope (documented) | unchanged |
| Idempotent re-run | **Was No, now Yes** | same #2535 root cause — every item misclassified as `conflict` before the fix |
| Resume after interruption | Yes | confirmed with a real mid-apply kill at 500 and 5000 secrets, not simulated |
| No secret value ever logged/printed | Yes | confirmed at 30/500/5000-secret scale, all value types |
| Migration itself produces a Keyorix audit entry | Yes | confirmed `secret.created` event per secret |
| Migration-origin distinguishable from manual-origin in audit | No | confirmed: `actor_type` is plain `"user"`, same as a manual create; filed `migration-gap`, low/medium severity |
| ACL policies → Keyorix roles | Not supported (documented) | no code path; product decision needed |
| AppRole/userpass/K8s auth roles → Keyorix machine identities | Not supported (documented) | no code path; product decision needed |
| Tokens → Keyorix machine tokens | Not supported (documented) | no code path; product decision needed |
| Audit device config | Not supported (documented) | no code path |
| Effective-access equivalence check | Not possible (no mapping exists) | depends on the four rows above; filed as one `migration-gap`, high severity |
| Other secrets engines (Transit/PKI/DB/SSH/Cubbyhole) | Not attempted (documented) | `vaultsource` only walks KV mounts |
| Performance/pagination at 5k+ secrets | Yes, correct | exact count match, no duplicates/missing, at ~1-2 min/pass; see dimension 10 |

## Explicitly out of scope for this spec (not re-litigated here)

- AWS/Azure/GCP cloud sources (`docs/migrate-from-cloud.md`) — separate tool paths, separate
  fidelity concerns, not this session's subject.
- Vault Enterprise namespaces beyond the flat `X-Vault-Namespace` header Vault itself
  documents — no recursive cross-namespace discovery exists or is claimed.
