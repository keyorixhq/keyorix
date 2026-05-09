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

# Frontend (keyorix-web repo)
npm run dev         # port 3000
npx tsc --noEmit
npx vitest run
```

---

## ADR Index

| ADR | Title | Status |
|---|---|---|
| ADR-001 | Project→Environment→Secret hierarchy (Namespace+Zone removed) | Decided |
| ADR-010 | KEK rotation with full re-encryption sweep | Decided |
| ADR-014 | Frontend feature-folder architecture | Decided |
| ADR-015 | Bundle splitting — vendor/router/query/ui chunks | Decided |
| ADR-016 | CLI active project context via `keyorix project use` | Proposed |
| ADR-017 | Environment CLI surface under `project env` | Proposed |
| ADR-019 | Hierarchy depth: three levels by design | Proposed |
| ADR-020 | Project detail page — mental-mode tabs | Proposed |

ADR-010 lives in `docs/`. ADR-014 onward live in `keyorix-private/adrs/`.

---

## DB Models (`internal/storage/models/models.go`)

`Project`, `Environment`, `User`, `Role`, `Permission`, `RolePermission`, `UserRole`,
`Group`, `UserGroup`, `GroupRole`, `SecretNode`, `SecretVersion`, `SecretAccessLog`,
`SecretMetadataHistory`, `Session`, `PasswordReset`, `Tag`, `SecretTag`, `Notification`,
`AuditEvent`, `Setting`, `SystemMetadata`, `StatsSnapshot`, `APIClient`, `APIToken`,
`RateLimit`, `APICallLog`, `ShareRecord`, `GRPCService`, `IdentityProvider`

---

## Known Pre-existing Test Failures (not regressions)

None — `go test ./...` passes clean as of May 9, 2026.
