# ADR-113: Retire legacy service accounts in favour of machine identities

**Status:** Accepted (retroactive — the engineering decision was taken
2026-07-03 in #552; this ADR records it and closes the last remaining piece,
the dead web UI)
**Date:** 2026-10-03
**Related:** ADR-027 (Personal Access Tokens), ADR-030 (machine-token
authentication), ADR-070 (web repo merge)

## Context

2026-05-10, f2b62e2b ("RBAC phase 1") introduced admin-managed **service
accounts**: an `APIClient` (a named credential holder with a hashed
`client_secret`) plus `APIToken`s issued under it, managed through
`server/http/handlers/service_accounts_handler.go` and the
`internal/core/service_accounts.go` business logic, with admin-only issuance/
rotation/revocation routes under `/api/v1/service-accounts`.

ADR-030 (2026-06-10) then introduced **machine identities**: a project-scoped,
RBAC-integrated, fully-audited non-human principal with its own hashed-bearer-
token credential type (`machine_identity_credentials`) and role grants
(`machine_identity_roles`), authorized through the same `AuthorizePrincipal`
path as every other request.

2026-07-03, #552 (f81997af) found that the service-account credential type
was **never actually wired into authentication**:
`server/middleware/auth.go`'s `validateToken` had no branch that ever accepted
an `APIClient`/`APIToken` secret — every service-account token that had ever
been issued was, and always had been, rejected by every protected endpoint. A
credential type nothing can authenticate with is not a reduced-functionality
feature; it is dead code with a UI in front of it. #552 removed the issuance/
management routes and their `internal/core` logic outright, named machine
identities (already shipped, already wired) as the intended replacement, and
deliberately **kept** the `APIClient`/`APIToken` GORM models and the KEK-
rotation sweep code (`internal/encryption/sweep_auth.go`'s `sweepAPIClients`/
`sweepAPITokens`) so that an already-deployed database with legacy rows in
those tables would not break on `admin migrate` or on a key-rotation sweep.

2026-08-03, ADR-070 merged the separate web frontend repository into this one
as `web/`. The merge brought its `ServiceAccountsPage` along — built against
the routes #552 had, by that point, already deleted two months earlier in the
Go backend's own history, but the two repositories' histories were
independent until the merge, so the web UI was never updated to match.
2026-09-15, #1888 noticed the page was non-functional and slapped an "under
construction" banner on it rather than removing it.

Issue #2486 (filed by the QA-2 session building a static web-call-vs-
`openapi.yaml` contract test) made the gap precise: `web/src/services/
serviceAccounts.ts` calls 7 endpoints —
`GET/POST /api/v1/service-accounts`,
`PUT/DELETE /api/v1/service-accounts/{id}`,
`GET/POST /api/v1/service-accounts/{id}/tokens`,
`DELETE /api/v1/tokens/{id}` —
none of which exist anywhere in `server/http/router.go`. This is not a docs
gap; the backend genuinely has no handler for any of them, and never will,
per the decision below.

A second, related defect surfaced while tracing this ADR's own scope:
`web/src/pages/admin/OIDCFederationSection.tsx` (a tab on the same
`ServiceAccountsPage`) calls a THIRD non-existent surface,
`/api/v1/oidc/trust`, to bind an OIDC trust configuration to a legacy
`service_account_id`. The real OIDC/Kubernetes-JWT federation feature shipped
under ADR-031, machine-identity-scoped
(`POST /projects/{id}/machine-identities/{machineId}/oidc-bindings`,
`machine_identity_oidc_bindings`) — a different API shape entirely, and one
`web/` never grew a UI for. `OIDCFederationSection` is not a "Kubernetes
service account" (a distinct, real concept this ADR does not touch) — it is
dead UI for the same retired credential type, and is retired alongside it in
the companion PR.

## Decision

**Service accounts (`APIClient`/`APIToken`) are retired as a product
feature.** Machine identities (ADR-030/ADR-031) are the one non-human
identity model going forward.

- **No service-account API.** `server/http/handlers/service_accounts_handler.go`
  and its routes stay deleted (#552); no replacement is planned.
  `TestServiceAccountRoutesRemoved` (`server/http/integration_test.go`) is the
  standing guard — it fails if any of the 5 issuance/management routes is ever
  re-registered.
- **The web UI is removed**, not fixed: `ServiceAccountsPage`,
  `APITokensPage` (which showed only service-account tokens — no PAT or
  machine-identity content existed on that page to preserve), and
  `OIDCFederationSection` (dead UI for the pre-ADR-031 API shape), plus their
  service/hook/type layers (`services/serviceAccounts.ts`,
  `types/serviceAccounts.ts`, `features/admin/useServiceAccounts.ts`) and
  tests. See the companion PR for the full file list. The old
  `/admin/service-accounts` and `/admin/api-tokens` URLs redirect to
  `/admin/machine-identities` rather than 404ing for anyone with an old
  bookmark or link.
- **What remains, and why:** the `APIClient`/`APIToken` GORM models
  (`internal/storage/models/models.go`) and the KEK-rotation sweep code
  (`internal/encryption/sweep_auth.go`) stay. Deleting them outright would
  break `admin migrate` and key-rotation on any already-deployed,
  self-hosted database that still has legacy rows in those tables — Keyorix
  does not control when or whether an operator upgrades, so "no production
  system has these rows" cannot be verified centrally the way it could for a
  hosted service. Keeping dead-but-harmless columns and a sweep function is a
  strictly safer failure mode than a migration that silently drops rows or a
  sweep that crashes on a table it no longer expects.
- **A later purge is appropriate, but needs its own gate, not a date.**
  Filed as #2541: once a migration step can positively confirm zero rows
  remain in `api_clients`/`api_tokens` on a given install (the same
  "completion marker" pattern `ReconcileAlertsWriteRole`'s
  `alerts_write_role_backfill_v1` uses — see ADR-110), the models and sweep
  functions can be dropped in that release. Until that check exists and
  reports clean, the tables and sweep stay — removing them on a timeline
  instead of a verified-empty check would trade a loud, safe failure for a
  silent one on exactly the self-hosted, operator-upgraded deployments this
  ADR is trying to protect. The check now exists (see "The verified-empty
  gate" below); the deletion itself is deferred (see "The deletion is
  deferred").

## The verified-empty gate (#2541 stage 1, #4638)

`recordLegacyServiceAccountsState`
(`internal/storage/migrate_legacy_service_accounts.go`) is the check the
bullet above asked for. It landed in #4638 (2026-11-22, d05a31a85).

**What it checks.** On every migration it counts the rows of `api_clients`
and `api_tokens`. A table that does not exist counts as zero: existence comes
from `migrateDatabase`'s up-front snapshot (`apiClientExists`/`apiTokenExists`,
`internal/storage/factory.go:826-827`), not from a fresh query, because a
later `tableExists` can return a spurious false on Postgres after a step has
created tables, and a spurious false would record a false "empty"
(`INV-STORAGE-migration-existence-snapshot-before-create`). A table absent
from the snapshot was created empty by that same migration (`createU1Tables`,
`internal/storage/migrate_system.go:95`), so zero is correct.

**The marker.** `system_metadata` key `service_accounts_purge_v1`, one value:
`empty`.

| Rows found | Effect |
|---|---|
| `api_clients` and `api_tokens` both zero (or absent) | upserts `service_accounts_purge_v1 = empty` (idempotent; every boot re-evaluates it) |
| any row in either table | deletes the marker, so it never outlives the state it records, and logs `WARNING: legacy service-account tables are not empty (api_clients: N rows, api_tokens: M rows) ...` naming the counts and the cleanup statements (back up first) |

**Warning, not failure — and why.** In neither case does the step fail the
migration, stop the boot or change a row of either table: it observes, it
does not purge. A check that failed on a non-empty table could block the
upgrade of a running install over data that is, by construction, dead (no
authentication path has accepted these credentials since v0.87.0, #552), and
the operator would have to delete rows by hand to get their server back. The
cost of a warning is that nothing forces an operator to act on it; that is
acceptable because the marker, not the operator, is what the deletion PR is
gated on. The warning's counts are the operator's own evidence.

**Where it runs.** From `migrateDatabase` (`internal/storage/factory.go`),
immediately before `recordSchemaEpoch`, on both paths: the existing-install
path (`factory.go:1037`) and the transactional fresh-install tail
(`factory.go:1226`). Backup restore does not carry the marker over: the
loader skips it when loading `system_metadata`
(`internal/backupfmt/loader.go:110`, skip at `loader.go:184`), because the
restoring server recomputes it on its own boot.

**Guards.** `TestLegacyServiceAccountsState_SQLiteUpgradePaths`,
`TestLegacyServiceAccountsState_RowsClearMarkerAndAreKept` and
`TestLegacyServiceAccountsState_PostgresUpgradePaths`
(`internal/storage/legacy_service_accounts_state_test.go`: fresh install plus
every release snapshot v0.91.0–v0.96.3) and
`TestNoLiveWriterForLegacyServiceAccountTables`
(`internal/storage/legacy_service_accounts_writer_guard_test.go:77`), which
fails if any non-test code builds an `APIClient`/`APIToken` row or writes
`INSERT INTO api_clients|api_tokens`. That guard does not see generic copies:
backup restore (`internal/backupfmt` `LoadArchive`, reflecting over
`storage.AllModels`) and the I6 old-release fixtures can still bring rows
back.

**What the marker proves and what it does not.** `empty` says the tables held
no rows at that database's last migration. It says nothing about a database
that has not been migrated by a gate-carrying binary yet, and a later restore
of an old archive can reintroduce rows (the next boot then clears the
marker). It is evidence for one install; it says nothing about installs the
project cannot see.

## The deletion is deferred

**Do not delete the `APIClient`/`APIToken` models, `sweepAPIClients`/
`sweepAPITokens` or the tables yet.** Decision (Andrei, 2026-10-17, on #2541):
they are dropped only **after the first pilot customer has upgraded** to a
release carrying the gate, so the first real self-hosted upgrade runs against
a binary that still understands the tables and the rows (if any) are
reported by the warning. The gate (stage 1) is on `main`; the deletion (stage
2, "PR 2") is **not for now**. #2541 stays open until stage 2 merges.

**Condition under which the deletion PR may go ahead — both must hold:**

1. the `service_accounts_purge_v1 = empty` marker is present on the installs
   in question (read `system_metadata` where `key = 'service_accounts_purge_v1'`
   on each, after it has booted a gate-carrying binary; absent marker means
   rows exist, or the install has not run the gate yet, and either way
   deletion is not cleared for that install), **and**
2. the first pilot customer has upgraded to a release carrying the gate.

Neither alone is enough: the marker without the upgrade proves nothing about
the customer who has not moved yet, and the upgrade without a clean marker
means a real install holds rows that would be dropped. The calendar is not a
condition.

## Worklist for the deletion PR

Every reference below was grepped on `main` at f04812fd3 (whole tree, whole-word
`APIClient`, `APIToken`, `sweepAPIClients`, `sweepAPITokens`, plus the table
names `api_clients`/`api_tokens`). Line numbers drift: re-run
`rg -n -w 'APIClient|APIToken|sweepAPIClients|sweepAPITokens|api_clients|api_tokens'`
at the start of the deletion PR and treat this list as the checklist, not as
a substitute for the search. `newAPIClient`, `*APIClient()` helpers in `cli/`
and `migrate/` and `cli/internal/apiclient` are an unrelated HTTP-client
concept and are not on this list.

### Non-test code

| Where | What it is | What must change |
|---|---|---|
| `internal/storage/models/models.go:1899`, `:1912` | the `APIClient` and `APIToken` types | delete both; `models.go:1463` only mentions `APIToken` in a comment about PATs: reword |
| `internal/storage/models/all_models.go:85-86` | model list for the guard registry | remove the two entries |
| `internal/storage/all_models.go:32-33` | `AllModels()`, the source of truth for backup, restore order and the all-tables guard | remove the two entries; this drops both tables from backups (see backup path below) |
| `internal/storage/migrate_system.go:95`, `:101-110` | `createU1Tables` creates both tables when missing; takes `apiClientExists, apiTokenExists` | remove both blocks and both parameters |
| `internal/storage/factory.go:826-827`, `:998`, `:1097` | the existence snapshot, the `createU1Tables` call, a comment listing the models | drop the two snapshot lines and arguments; reword the comment |
| `internal/storage/factory.go:1037`, `:1226`; `internal/storage/migrate_legacy_service_accounts.go:21-81` | the gate itself | remove the two calls and the file once nothing remains to count (the PR must also decide the fate of the existing `service_accounts_purge_v1` row: leaving it is harmless, `loader.go:184` still skips it; deleting it needs a migration step) |
| `internal/storage/factory_schema_epoch.go:28` (`currentSchemaEpoch = 10`) | schema epoch (ADR-097/101) | a dropped table is a schema change: follow the epoch rules, which add `internal/storage/testdata/schema_epoch/epoch-<N>.{sqlite,postgres}.txt` (today `epoch-8`, `-9`, `-10` all list `api_clients`/`api_tokens`, e.g. `epoch-10.sqlite.txt:852-853`) |
| *(new)* a drop step in `migrateDatabase` | nothing drops these tables today; `AutoMigrate` removal alone leaves them in every existing database | the PR decides: an explicit `DROP TABLE` on installs whose marker is `empty` (and refusing or warning when rows exist), or leave the orphan tables in place. Dropping must happen inside the same transaction discipline as the other steps |
| `internal/encryption/sweep_auth.go:45` (`sweepAPITokens`), `:104` (`sweepAPIClients`), comments `:4`, `:10`, `:21` | KEK-rotation sweep for the two tables | delete both functions and the comments that mention them |
| `internal/encryption/sweep.go:32-33` (`APITokensSwept`, `APIClientsSwept`), `:61-72` (the two calls and their error wraps) | `SweepAllTables` result fields and calls | remove the calls and fields; `LegacyAADUpgraded += legacyAPITokens` goes with them |
| `internal/encryption/sweep_verify.go:54`, `:101-102`, `:170-205` (`readSweptAPITokens`, `readSweptAPIClients`), `:306` | post-sweep verification readers and the sweep total | remove both readers, their entries in `sweptTableReaders`, and the two terms in the total |
| `internal/encryption/dek_epoch.go:375` | `sweptModels()`: the tables locked during a rotation | remove the two models (`TestSweptModels_MatchSweptFields` keeps it in step with the sweep) |
| `internal/encryption/service_rotation.go:202-204` | "Sweep committed" log line printing both counts | drop the two counts from the format and arguments |
| `internal/encryptionops/dek.go:331-332` | rotation summary line printing both counts | same |
| `internal/encryptionops/auth_encryption.go:69-95` (`ShowAuthEncryptionStats`), `:307` | operator stats print "API Clients"/"API Tokens" counts via `db.Model(&models.APIClient{})`/`APIToken` | remove both blocks; reword the `:307` comment |
| `server/http/router.go:1099-1107` | comment saying the models and sweep are left in place for legacy databases | delete the comment (do not delete `TestServiceAccountRoutesRemoved`, `server/http/integration_test.go`) |
| `internal/backupfmt/order.go:39`, `:40`, `:44` | `referenceOverrides` entries naming `APIClient` as the referenced model (`APICallLog.ClientID`, `APIToken.ClientID`, `RateLimit.ClientID`) | remove the `APIToken` entry with the model. `APICallLog` and `RateLimit` (`models.go:1925`, `:1933`) are separate legacy models with a `ClientID` that references `APIClient.ID` and no non-test user outside migration and `AllModels`: decide in the same PR whether to drop them too or reclassify `ClientID` (`TestRestoreOrder_EveryReferenceFieldIsClassified` fails on a stale override and on an unclassified ID-shaped field) |
| `internal/backupfmt/loader.go:100-110`, `:171`, `:184` | comments and the marker skip | remove only when the marker row is no longer written; keep the skip while any deployed database can still hold it, since an archive made by a gate-carrying binary contains that row |
| `migrations/001_init.sql:232`, `:243`, `:256`, `:264`; `migrations/004_add_auth_encryption.up.sql:13-39`, `.down.sql:25-71`; `migrations/011_drop_session_reversible_encryption.up.sql:12-13` | historical SQL migrations that create and alter both tables and have foreign keys from two other tables (`001_init.sql:256`, `:264`) | do not edit applied migrations. Check what still runs them (`migrations/migrations_test.go` seeds both tables at `:159-210`); a new numbered migration may be needed if they are live, otherwise leave them as history |
| `docs/state-map/stores.tsv:15-16` | state-map rows for the two models | remove the rows |
| `keyorix-core.md:78` | model inventory | remove the two names |
| `docs/adr-010-kek-rotation-reencryption-sweep.md:68-69`, `:72`, `:98-99`, `:249`; `docs/operator/j6-key-rotation.md:36`, `:52`, `:56` | rotation docs listing the two tables in the sweep order and in sample output | update the table, step list and sample output to the new sweep output |
| `docs/adr-027-personal-access-tokens.md:15-30`, `:93-94` | historical contrast with `APIToken` | no change needed: they describe the past |
| `web/` | no reference to `APIClient`/`APIToken`/`api_clients`/`api_tokens` | none (the UI was retired in this ADR's companion PR) |

### Test code

Production-code deletion makes all of these fail to compile or fail on
purpose; each must be deleted or reduced.

| File | Lines | What | What must change |
|---|---|---|---|
| `internal/storage/legacy_service_accounts_state_test.go` | `:4`, `:36-40`, `:73-180` | the three gate tests | delete with the gate |
| `internal/storage/legacy_service_accounts_writer_guard_test.go` | `:4-142` (guard at `:77`, calibration at `:125`) | the no-live-writer guard | delete (nothing left to write to); its premise disappears with the types |
| `internal/storage/all_models_migration_guard_test.go` | `:27` | comment naming both models | reword the count in the comment; the guard itself compares `AllModels()` with the live tables |
| `internal/storage/store/child_parent_liveness_registry_test.go` | `:81` | registry entry for `APIClient` | remove |
| `internal/storage/store/secret_metadata_cache_dek_sweep_invalidation_test.go` | `:82` | table list handed to a sweep test | remove both models |
| `internal/storage/store/secret_version_cache_epoch_guard_test.go` | `:84` | `api_tokens` in a table list | remove |
| `internal/storage/models/sensitive_json_test.go` | `:45-51` | the two JSON-redaction cases | remove both cases |
| `internal/encryption/encryption_s23_test.go` | `:8-9`, `:51-52`, `:410-470`, `:573-581`, `:722-748`, `:810-870` | sweep tests (dry-run, skip-empty, corrupt, decrypt-error) | delete the `sweepAPIClients`/`sweepAPITokens` tests; drop the models from the migrate list |
| `internal/encryption/encryption_s24_test.go` | `:4-6`, `:58-59`, `:105-113`, `:154-213`, `:959-981` | skip-empty, happy-path, error-propagation tests | same |
| `internal/encryption/encryption_s25_test.go` | `:5`, `:60-61`, `:178-209`, `:365`, `:881`, `:1020-1076`, `:1202-1266` | deserialize, `Updates()` error and read-only-view tests; an assertion on `APITokensSwept` | same; remove the `APITokensSwept` assertion |
| `internal/encryption/encryption_s2_test.go` | `:39-41`, `:780-781`, `:809`, `:976-1006` | model lists and `TestService_RotateDEKWithSweep_AuthTables` | remove the models; drop the token part of the rotation test |
| `internal/encryption/g80_coverage_test.go` | `:997-1073` | `sweepAPITokens`/`sweepAPIClients` coverage tests | delete |
| `internal/encryption/auth_encryption_test.go` | `:29-31`, `:151`, `:190`, `:203-220` | model lists and a `sweepAPIClients` re-encrypt test | remove the models and the sweep test; the `EncryptAPIToken`/`DecryptAPIToken` tests (`:96-113`) test `AuthEncryption` helpers and are a separate decision (the helpers are not in this list because they are not the models) |
| `internal/encryption/sweep_completeness_test.go` | `:51`, `:60-61` | the swept-field completeness table | remove both entries |
| `internal/encryption/sweep_test.go` | `:45-46` | migrate list | remove |
| `internal/encryption/atrest_memory_canary_fuzz_test.go` | `:237` | migrate list | remove |
| `internal/encryption/keymanager_sweep_crash_consistency_fuzz_test.go` | `:75` | table names in a fuzz harness | remove |
| `internal/encryptionops/testhelpers_test.go` | `:73-74` | migrate list | remove |
| `server/http/sharing_integration_test.go` | `:63-64` | migrate list | remove |
| `server/http/integration_test.go` | `:682` | comment in `TestServiceAccountRoutesRemoved` | reword; keep the test |
| `migrations/migrations_test.go` | `:159-210` | seeds and asserts both tables through the SQL migrations | follows the decision on `migrations/*.sql` above |
| `internal/backupfmt/i6_oldarchive_fuzz_test.go` | `:179` | `api_tokens` in `i6ContentTables` | remove from the digest list |
| `server/admin/i6_restore_oldversion_test.go` | `:196` | counts `api_tokens` after restoring an old archive | remove the row; see backup path below |
| `scripts/i6-gen/zz_i6gen_test.go.txt` | `:211` | generator for the old-release fixtures builds a `models.APIToken` | the fixtures are generated by OLD code, so this stays tied to the old release's model; adjust the generator note and re-check that fixtures still load |
| `internal/storage/testdata/upgrade-snapshots{,-pg}/v0.91.0 … v0.96.3/snapshot.sql` | whole files | historical release snapshots that create and may populate both tables | do not edit: they are the point of the upgrade tests. The deletion PR's own upgrade test must show a snapshot that holds the tables (and rows) still migrates |

### Backup, restore, export, migration, doc paths

- **Backup/restore:** both tables are in `storage.AllModels()`
  (`internal/storage/all_models.go:32-33`), so `internal/backupfmt` writes
  them into every archive and restores them in dependency order. Removing the
  models stops new archives carrying them, but **an archive made by an older
  release still contains `api_clients`/`api_tokens` entries and its rows.**
  The PR must define what restore does with an entry whose table no longer
  exists (`internal/backupfmt/loader.go`, `checks.go`, `order.go`) — ignore
  with a logged count, or refuse — and extend the I6 old-archive tests
  (`internal/backupfmt/i6_oldarchive_fuzz_test.go`,
  `server/admin/i6_restore_oldversion_test.go`) to prove it. Restoring an old
  archive with rows into a database whose tables were dropped must not silently
  lose or fail on them without saying so.
- **Export:** no export path names either model outside `AllModels()`
  (whole-tree grep: no other non-test reference).
- **Migration:** see the drop-step row above; nothing drops the tables today.
- **Rollback:** a binary from before the deletion runs `AutoMigrate` for both
  models (`migrate_system.go:101-110`) and recreates empty tables, so
  rolling back one release is safe; rolling back across the epoch bump falls
  under ADR-097/101.
- **Docs:** `docs/adr-010-kek-rotation-reencryption-sweep.md` and
  `docs/operator/j6-key-rotation.md` (rows above); add an `upgrading.d/`
  note when the deletion ships.

### ADR-027 cross-reference

ADR-027's "What this is not" section says "Not service accounts (those
remain admin-managed, see `service_accounts_handler.go`)" — written before
#552 deleted that handler. Updated in this PR to point here instead.

## Consequences

- One non-human identity model (machine identities) instead of two, one of
  which never worked.
- No `/api/v1/service-accounts*` or `/api/v1/oidc/trust` API, now or planned;
  `internal/core`/`server/http` carry no service-account business logic.
  `TestServiceAccountRoutesRemoved` keeps it that way.
- The web admin UI no longer has a page that always fails every action a
  user takes on it against a real backend (the defect issue #2486 reported).
- `APIClient`/`APIToken` DB models and the KEK-rotation sweep remain as
  dead-row-safe legacy support. The verified-empty check has landed (#4638),
  but the deletion is deferred until the marker is `empty` on the installs in
  question and the first pilot customer has upgraded (2026-10-17 decision on
  #2541); the worklist above is its checklist.
- Anyone who previously bookmarked `/admin/service-accounts` or
  `/admin/api-tokens` lands on Machine Identities instead of a 404.
