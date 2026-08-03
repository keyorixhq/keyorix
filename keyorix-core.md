# Keyorix — Contributor Reference

**Product:** Lightweight on-premise secrets manager — Vault alternative for teams that can't
use SaaS and won't maintain Vault.

---

## Repo Layout

| Path | Purpose |
|---|---|
| `cmd/` | Entry points — `keyorix` CLI and `keyorix-server` |
| `internal/cli/` | CLI command tree (cobra) |
| `internal/client/` | HTTP client for CLI→server calls |
| `internal/config/` | Config loading (env + YAML) |
| `internal/core/` | Domain services — users, secrets, projects, encryption |
| `internal/di/` | Wire-based dependency injection |
| `internal/encryption/` | AES-256-GCM envelope encryption, KEK rotation |
| `internal/i18n/` | Localisation (EN/ES/FR/DE/RU) |
| `internal/securefiles/` | Encrypted local credential store |
| `internal/startup/` | Server bootstrap and migration runner |
| `internal/storage/` | GORM models, PostgreSQL + SQLite adapters |
| `internal/utils/` | Shared helpers |
| `server/http/` | Chi router, handlers, middleware |
| `server/grpc/` | gRPC service stubs |
| `server/middleware/` | Auth, RBAC permission enforcement |
| `server/validation/` | Input validators |
| `migrations/` | SQL migration files |
| `docs/` | ADRs and reference docs |
| `web/` | Dashboard frontend (React/TS/Vite, pnpm) — in-repo subtree since ADR-070 |

---

## Dev Commands

```bash
# Backend server
KEYORIX_DB_PASSWORD=xxx go run server/main.go

# Build
make build          # keyorix (CLI) + keyorix-server
make build-cli
make build-server

# Test
go test ./...
go test -race ./...

# Frontend (web/, ADR-070)
pnpm --dir web dev         # port 3000
pnpm --dir web type-check
pnpm --dir web test --run
```

---

## ADR Index

| ADR | Title | Status |
|---|---|---|
| ADR-001 | Project→Environment→Secret hierarchy (Namespace+Zone removed) | Decided |
| ADR-010 | KEK rotation with full re-encryption sweep | Decided |
| ADR-014 | Frontend feature-folder architecture | Decided |
| ADR-015 | Bundle splitting — vendor/router/query/ui chunks | Decided |
| ADR-016 | CLI active project context via `keyorix project use` | Implemented |
| ADR-017 | Environment CLI surface under `project env` | Implemented |
| ADR-019 | Hierarchy depth: three levels by design | Implemented |
| ADR-020 | Project detail page — mental-mode tabs | Proposed |

ADR-010 lives in `docs/`. ADR-014 onward live in `keyorix-private/adrs/`.

---

## DB Models (`internal/storage/models/models.go`)

`Project`, `Environment`, `User`, `Role`, `Permission`, `RolePermission`, `UserRole`,
`Group`, `UserGroup`, `GroupRole`, `SecretNode`, `SecretVersion`, `SecretAccessLog`,
`SecretMetadataHistory`, `Session`, `PasswordReset`, `Tag`, `SecretTag`, `Notification`,
`AuditEvent`, `Setting`, `SystemMetadata`, `StatsSnapshot`, `APIClient`, `APIToken`,
`RateLimit`, `APICallLog`, `ShareRecord`, `GRPCService`, `IdentityProvider`,
`ExternalIdentity`, `AnomalyAlert`, `RotationPolicy`

**RBAC Phase 2 — scoped authorization.** `UserRole` and `GroupRole` carry
`ProjectID`/`EnvironmentID` (uint, `0` = global sentinel) in their composite
primary key. Enforcement is lazy and per-request: `core.Authorize(ctx, userID,
permission, Scope)` (`internal/core/authz.go`) resolves the roles that apply at
the target scope (direct + group-inherited), with a global `admin`/`super_admin`
bypass. HTTP routes use `middleware.RequireScopedPermission(permission,
resolver)` — resolvers derive the target project/env from the path (secret, env,
project, share, rotation-policy) — while create routes authorize in-handler
against the request body. Migration `008` adds the `environment_id` column for
existing DBs; fresh installs get the full composite PK via AutoMigrate.

`RotationPolicy` is created by a standalone migration step in
`internal/storage/factory.go` (not the guarded full `AutoMigrate` list) so a fresh
Postgres DB's first boot doesn't re-inspect the just-created table and trip the
pgx "insufficient arguments" bug.

---

## Known Pre-existing Test Failures (not regressions)

None — `go test ./...` passes clean as of June 3, 2026 (full gate: build, vet,
gofmt, tests, gosec MEDIUM+, and a runtime Postgres migration check on a fresh DB).
