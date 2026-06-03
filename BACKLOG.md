# Keyorix Backlog

Working list of upcoming and deferred work. Newest decisions at the top of each
section. For architectural rationale see the ADRs (`docs/` and
`keyorix-private/adrs/`).

## In progress / next

_(nothing claimed)_

## Done

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
- **CLI scope flags** — add `--project` / `--environment` to the `keyorix rbac`
  assign/remove commands. The HTTP API and remote storage client already carry
  scope in the payload; only the CLI surface is missing.
- **OpenAPI sync** — document the new optional `project_id` / `environment_id`
  fields on `POST /user-roles`, `PUT /users/{id}/roles`, and
  `POST /groups/{id}/roles`.
- **Upgrade-path PK rebuild** — fresh installs get the full composite primary key
  via AutoMigrate, but an existing GORM-created DB keeps its old
  `(user_id, role_id)` PK, so the same role cannot be assigned at two scopes
  there. Provide a one-off migration that rebuilds the `user_roles` /
  `group_roles` primary key to include `project_id` / `environment_id`
  (SQLite requires table recreation; Postgres an `ALTER`).
- **Scoped list UX** — an unscoped `GET /secrets` by a non-global reader returns
  403; consider instead returning the union of secrets across the scopes they can
  read (requires a readable-scopes query + result filtering, with a log line when
  results are truncated).

### RBAC Phase 3 (proposed)
- Per-folder / per-secret ACLs (Vault-path-style depth).
- Scope `Group` membership itself to a project.

### Other
- **Rotation policy execution** — `EvaluateRotationPolicies` is reachable only via
  a GET endpoint; nothing runs it on a schedule, and the `Notification` model is
  never written. Wire a background sweep that flags overdue secrets and emits
  notifications.
- **gRPC services** — `server/grpc/services/*` are `codes.Unimplemented` stubs;
  implement against the core service if/when gRPC is on the roadmap.
- **ADR-020** — project detail page (frontend, `keyorix-web`), still Proposed.
