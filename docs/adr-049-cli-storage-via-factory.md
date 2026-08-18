# ADR-049: CLI commands must obtain storage via the factory

## Status

Accepted. (ADR-048 was assigned to the CGO-free SQLite driver decision; this
decision took the next free number.)

**Partially superseded by ADR-083** (`storage.type: remote` is CLI/client mode
only, **Accepted**): this ADR's own Decision — CLI commands must obtain
storage via the shared factory — is unaffected and remains in force. What
ADR-083 retires is a *later* assumption, never actually decided here, that
grew up around this ADR number in code comments: that `storage.type: remote`
also supports "a full downstream Keyorix server." This ADR never made that
claim (re-read above — it is scoped entirely to CLI subcommands bypassing the
factory); ADR-083 is the explicit, formal retirement of that assumption
wherever it was informally anchored to this ADR number. See ADR-083 for the
investigation.

## Context

Keyorix has a single storage seam: `storage.NewStorageFactory().CreateStorage(cfg)`
switches on `cfg.Storage.Type` (`remote` / `postgres`(`postgresql`) / `local`(default
SQLite)) and returns a `storage.Storage` over the right backend, applying connection-pool
settings and the full migration set. The server, and the newer CLI entry points
(`internal/cli/modes.go`, `internal/cli/common/common.go` via `InitializeCoreService`),
all go through this factory, so they honor the operator's configured backend.

A set of older CLI subcommands do not. They open the database directly with
`gorm.Open(sqlite.Open(cfg.Storage.Database.Path), …)`, hardwiring SQLite and ignoring
`cfg.Storage.Type` entirely:

    internal/cli/encryption/auth_encryption_stats.go   (openDatabase — pure SQLite, ignores Type)
    internal/cli/rbac/{assign_role,remove_role,check_permission,
                       list_permissions,list_roles,list_user_roles}.go
    internal/cli/secret/{update,delete,versions}.go
    internal/cli/share/{create,list,update,revoke,shared_secrets,group_shares}.go

(`internal/cli/encryption/encryption.go` is a near-miss: its `openDBForRotation` already
switches on `cfg.Storage.Type` and handles Postgres, but it still imports the SQLite
driver directly and re-implements the factory's connection/pool logic.)

This is a **latent correctness bug**. Against our production-default Postgres backend,
every one of these subcommands silently opens (or *creates*) a local `secrets.db` SQLite
file and operates on an empty, wrong database instead of talking to Postgres. The command
appears to succeed — it just touched the wrong store. For an air-gapped operator who
typo's `storage.type`, the failure mode is equally quiet.

The config-resolution path is *not* the problem: `config.LoadConfig()` is literally
`Load("")`, the same call `InitializeCoreService` uses, and both honor
`KEYORIX_CONFIG_PATH`. Backend selection is driven only by the `storage.type` YAML field
(there is no env override for the backend). So the only divergence is the storage-open
step — these commands bypass the factory.

## Decision

**CLI commands must obtain their database access through the storage package. Direct
driver opens (`gorm.Open(sqlite.Open(...))`, `postgres.Open(...)`) in CLI command files
are prohibited.** Backend selection belongs to one place — the factory — keyed off
`cfg.Storage.Type`.

There are two sanctioned entry points, both of which honor `cfg.Storage.Type`:

- **`common.InitializeStorage()` → `storage.Storage` (the normal case).** Loads config via
  the same `config.Load("")` path as the rest of the CLI and returns
  `NewStorageFactory().CreateStorage(cfg)`. Commands that need the core service wrap it
  with `core.NewKeyorixCore(st)`; commands that talk to storage directly (e.g. RBAC
  `ListRoles`) use the returned `storage.Storage`. This replaces the per-command
  `gorm.Open` + ad-hoc partial `AutoMigrate` + `store.NewLocalStorage` dance — the factory
  already runs the full, idempotent migration set.

- **`storage.OpenGormDB(cfg)` → `*gorm.DB` (the rare raw-DB case).** A small helper in the
  `internal/storage` package (the factory's own package — *not* a CLI file) that opens a
  `*gorm.DB` for the configured local backend, switching on `cfg.Storage.Type` and applying
  the same pool settings as the factory. It exists for the two encryption admin commands
  that legitimately need a raw `*gorm.DB`: the DEK rotation sweep (`RotateDEKWithSweep`
  owns its own transaction — ADR-010) and the auth-encryption statistics counters
  (`db.Model(...).Count(...)`). These genuinely cannot use the `storage.Storage` abstraction,
  but they still must not hardwire SQLite — so the driver selection moves *into the factory
  package* and out of the CLI command files. Remote storage has no local `*gorm.DB`; these
  host-local admin commands already require a non-remote backend.

The crucial property either way: **the SQLite and Postgres driver imports live only in the
`internal/storage` package** (the factory and its sibling `OpenGormDB` helper). No CLI
command file imports a GORM driver or decides which backend to open.

## Scope / non-goals

- **SQLite stays.** It remains a fully supported embedded / air-gapped / test backend. This
  ADR removes the *bypass*, not the backend.
- **The factory is unchanged.** `internal/storage/factory.go` keeps all three backends and
  its default-backend behavior. `OpenGormDB` is an additive sibling; it does not alter
  `CreateStorage`.
- **No new config knob.** Backend selection stays driven solely by `storage.type`. No
  `KEYORIX_STORAGE_TYPE` or Viper `AutomaticEnv` is introduced.
- The factory's `default`-case treatment of *unknown* `storage.type` values (currently
  folded into SQLite) is a separate footgun tracked as its own follow-up ADR — explicitly
  out of scope here.

## Alternatives considered

- **Add a `DB()` accessor to `storage.LocalStorage`** so the encryption commands can reach
  the raw `*gorm.DB` through the abstraction. Rejected: it leaks the GORM handle through an
  interface that exists precisely to hide it, and would also need a meaningless
  implementation on `RemoteStorage`. A factory-package `OpenGormDB` keeps the raw handle a
  storage-layer concern without widening the `Storage` interface — consistent with the
  existing decision (ADR-010 addendum) to keep raw-DB rotation a private helper rather than
  a storage accessor.
- **Leave the encryption commands as-is** because `encryption.go` already handles Postgres.
  Rejected: `auth_encryption_stats.go` is still pure-SQLite, and both files duplicate the
  factory's connection logic and import the driver directly — exactly the bypass this ADR
  closes. Centralizing the open keeps a single source of truth for how Keyorix connects.

## Consequences

- Every CLI subcommand honors `cfg.Storage.Type`: a Postgres-backed deployment is reachable
  from the CLI, and no command silently creates a stray `secrets.db`.
- Driver selection and pool configuration have one home (`internal/storage`). Adding or
  changing a backend is a factory-package change; CLI commands are unaffected.
- Per-command partial `AutoMigrate` calls disappear — commands inherit the factory's
  complete, idempotent migration set, removing a class of "table not found" drift between
  CLI and server.
- Tests continue to construct SQLite in-memory storage directly; that is intended and
  unaffected (the prohibition is about production command paths, not test setup).
