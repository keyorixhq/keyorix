# Keyorix Backlog

Working list of upcoming and deferred work. Newest decisions at the top of each
section. For architectural rationale see the ADRs (`docs/` and
`keyorix-private/adrs/`).

## In progress / next

## Done

- **Deleted the orphaned `keyorixhq_keyorix-web` SonarCloud project.**
  ADR-070's Sonar setup was reversed: `web/` is analyzed as part of the
  single `keyorixhq_keyorix` project (see ADR-070 Consequences) rather than
  its own project, because the separate-project setup required an org-admin
  rebind that never happened and permanently failed SonarCloud on every PR
  touching `web/**`. `keyorixhq_keyorix-web` had nothing pointing at it;
  deleted via the SonarCloud UI (org-admin action). Verified via the
  SonarCloud API: `GET api/components/show?component=keyorixhq_keyorix-web`
  now returns "Component key 'keyorixhq_keyorix-web' not found".

- **Per-binary CycloneDX SBOMs for release binaries.** Reimplemented commit
  `9eceffe4`'s intent (it had drifted too far from current `Makefile`/
  `release.yml` — 14 commits touched those files since it forked — to
  cherry-pick cleanly): `make release` now generates a CycloneDX 1.6 SBOM per
  binary (`keyorix_sbom.cdx.json`, `keyorix-server_sbom.cdx.json`, via
  `cyclonedx-gomod app` in app mode) before the checksums step, so both are
  covered by `checksums.txt` and uploaded with the existing `dist/*` glob. A
  standalone `make sbom` target does the same outside a full release.
  `release.yml` installs `cyclonedx-gomod@v1.10.0` (confirmed still the
  latest available version) on PATH first. SECURITY.md documents this.
  Verified: ran the actual tool locally, not just the Makefile syntax — both
  SBOMs are valid CycloneDX 1.6 with real dependency graphs (112/125
  components for CLI/server) and full license evidence (112/112 and
  125/125 components carry `evidence.licenses`), and a full `make release`
  run confirms both SBOM files land in `checksums.txt` and the web-UI
  placeholder restore still leaves a clean working tree.

- **Verified: the two gitleaks findings flagged as possibly re-flagging from
  the `keyorix-web` import (ADR-070) do not.** Ran `gitleaks detect --source .
  --verbose --redact --log-opts="HEAD"` (CI's exact invocation) against
  current history: "no leaks found". The path-based allowlist patterns added
  to root's `.gitleaks.toml` during the merge cover it.

- **`stunit` connection-pool safety fix (ADR-069 investigation closed).**
  `server/http/handlers/secret_templates_unit_test.go`'s `newFailingSTHandler`
  was missing `SetMaxOpenConns(1)` on its `cache=private` in-memory SQLite
  connection — the same class of gap already fixed in
  `internal/storage/store/local_transaction_test.go` and
  `local_usage_test.go` for the identical pattern (`cache=private` gives each
  new physical connection its own empty database; without pinning to one
  connection, a pool-rotated connection from a later handler call in the same
  test could see neither the migrated schema nor the seed row). Fixed to
  match. The originally-reported symptom — an actual on-disk file named
  `stunit` (no counter suffix) — could **not** be reproduced despite an
  extensive attempt: isolated `database/sql` DSN test, isolated
  GORM+dialector+AutoMigrate test, this file's tests run alone, the full
  `server/http/handlers` package, all four both with and without `-race`,
  and on both macOS and Linux (`golang:1.26.5-alpine`, matching the CI
  runner). No other file in the repo uses this DSN pattern. Most likely a
  one-off/environmental artifact from whenever it was originally observed,
  not a live, reproducible bug in the current code — closing the
  investigation rather than leaving it open indefinitely, but flagging that
  if a stray `stunit` file is ever seen again, this fix's own reasoning
  (connection-pool rotation touching a "private" cache) is the first thing
  to revisit, not the DSN string construction, which was verified correct
  across every reproduction attempt.

- **OpenAPI sync (RBAC scope fields)** — `project_id` / `environment_id` are
  documented on `POST /user-roles`, `PUT /users/{id}/roles`, and
  `POST /groups/{id}/roles` in `server/http/handlers/openapi.yaml`. Shipped in
  PR #1152, before this item was added to the backlog below — stale entry
  removed.
- **FinOps / billing report** — `GET /api/v1/admin/billing/report?from=&to=` and
  `keyorix billing report --from --to` CLI command. Date-range per-project
  breakdown: secret counts, reads, writes, rotations, unique human users, machine
  reads. Gated behind `FeatureBilling = "billing"` license feature.
  `internal/core/billing.go`, `internal/storage/store/local_billing.go`,
  `server/http/handlers/admin_billing.go`, `internal/cli/billing/`.
  PR [#1227].
- **Dashboard stat-card trends** — `DeploymentStatsSnapshot` extended with 4 new
  metrics (audit logins, secret reads, failed auth attempts, inactive users);
  `DashboardStats` gains 8 prev+trend fields for all 6 deployment metrics.
  `saveDeploymentSnapshot` wires full trend computation. PR [#1226].
- **Secret `--type` update via CLI** — `UpdateSecretRequest.Type` wired through
  core → HTTP handler → CLI `keyorix secret update --type`; audit diff records
  before/after. PR [#1225].
- **Password expiry hard gate** — `enforcePasswordExpiryGate` wired into `Login`
  and `VerifyMFALogin`: when `max_age_days` is exceeded for an active user, the
  account state is transitioned to `password_reset_required` before the session is
  minted, so `EnforceAccountRestriction` blocks all subsequent API requests.
  Fails closed on storage error. ADR-025. Commit 871cc520.
- **Scoped list UX** — ACL-only users (no project role) now see their
  per-secret / per-folder ACL-granted secrets on both scoped
  (`?project_id=X`) and unfiltered `GET /secrets` requests. Previously
  the scoped path returned 403 and the unfiltered path returned an empty
  list; both now call `ListSecretsWithSharingInfo` which already enforces
  access through owned + ACL-granted filtering. PR #1151.
- **RBAC Phase 3 — per-folder / per-secret ACLs** — `internal/core/secret_acl.go`:
  `SecretACL` model + `GrantSecretACL` / `RevokeSecretACL` / `ListSecretACLs` /
  `HasSecretACL`; folder-grant inheritance walks the ancestor chain
  (`GetSecretAncestors`). Storage: `ListSecretACLsByUser` inverse query. Listing
  integration in `getACLGrantedSecretsWithSharingInfo` with BFS folder expansion.
  HTTP handlers in `secret_acl_handler.go`. ADR-066.
- **RBAC Phase 3 — project-scoped Group membership** — `UserGroup.ProjectID`
  scopes memberships to a project (`0` = global). `RemoveUserFromGroup` and
  `applyGroupMembershipChanges` carry the scope; authz inheritance already
  resolves correctly.
- **CLI scope flags** — `--project` / `--environment` on `keyorix rbac assign-role`
  and `remove-role`; `--environment` requires `--project`. Group role commands
  carry the same flags.
- **Rotation policy execution** — background sweep (`rotation_reminders.go`)
  calls `EvaluateRotationPolicies` on a schedule wired in `server/main.go:1016`;
  `RunAutoRotation` executes wave-ordered auto-rotate jobs.
- **gRPC services** — all 13 services in `server/grpc/services/` are fully
  implemented; `UnimplementedXxxServer` embedding is the Go forward-compat
  pattern, not a stub.
- **RBAC PK rebuild migration** — `migrateDatabase` now detects when
  `user_roles`/`group_roles` carry the old `(user_id, role_id)` or
  `(user_id, role_id, project_id)` primary key (from GORM-created pre-Phase-2
  installs) and rebuilds it to the full four-column composite PK
  `(user_id/group_id, role_id, project_id, environment_id)`. SQLite uses a
  CREATE/INSERT/DROP/RENAME recreation; Postgres uses DROP CONSTRAINT / ADD
  PRIMARY KEY. Runs after the Phase 2 NULL-normalise block; idempotent on every
  subsequent boot. Added in `internal/storage/factory.go`
  (`rebuildRolePKIfNeeded`, `rebuildRolePKSQLite`, `rebuildRolePKPostgres`).
- **RBAC Phase 2 — environment-scoped enforcement.** Permissions are resolved
  per-request against the target project/environment (`core.Authorize`), with
  group inheritance and a global `admin`/`super_admin` bypass. `UserRole`/
  `GroupRole` carry `ProjectID`/`EnvironmentID` (`0` = global) in a composite PK;
  migration `008` adds the column for existing DBs. HTTP routes enforce via
  `middleware.RequireScopedPermission` (path-resolved scope) or in-handler
  `Authorize` (body-resolved scope). Bootstrap now seeds an `editor` role.
- **RBAC Phase 1** — real DB-backed role/permission management, service accounts,
  rotation-policy CRUD, user-role assignment.

## Backlog

### Other
- **ADR-020** — project detail page (frontend, `web/`), still Proposed.
- **Refactor candidates (cyclomatic complexity)** — see
  [`docs/REFACTOR-CANDIDATES.md`](docs/REFACTOR-CANDIDATES.md). 55 functions
  above CCN 15 (`lizard`-generated, 2026-07-30), worst outliers
  `migrateDatabase` (CCN 182) and `initializeCoreService` (CCN 108). Not a
  dedicated-sweep item — fix opportunistically when already touching one of
  these functions.

[#1225]: https://github.com/keyorixhq/keyorix/pull/1225
[#1226]: https://github.com/keyorixhq/keyorix/pull/1226
[#1227]: https://github.com/keyorixhq/keyorix/pull/1227
