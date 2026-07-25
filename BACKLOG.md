# Keyorix Backlog

Working list of upcoming and deferred work. Newest decisions at the top of each
section. For architectural rationale see the ADRs (`docs/` and
`keyorix-private/adrs/`).

## In progress / next

_(nothing claimed)_

## Done

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

### RBAC follow-ups (from Phase 2)
- **OpenAPI sync** — document the new optional `project_id` / `environment_id`
  fields on `POST /user-roles`, `PUT /users/{id}/roles`, and
  `POST /groups/{id}/roles`.

### Other
- **ADR-020** — project detail page (frontend, `keyorix-web`), still Proposed.
- **FinOps / billing** — no `internal/billing/` or equivalent; no
  chargeback / usage-by-team reporting. Required for enterprise multi-team
  deployments.
