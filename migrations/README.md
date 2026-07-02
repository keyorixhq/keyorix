# migrations/ — legacy, manual-only upgrade path (NOT the live schema mechanism)

**The authoritative, always-on schema mechanism is GORM `AutoMigrate`**, driven by
`internal/storage/factory.go` (`migrateDatabase`, called from `createLocalStorage` /
`createPostgresStorage`). It runs automatically on every server boot, is idempotent,
and is additive on existing databases (it adds missing tables/columns/indexes; it
never drops anything). For any current or fresh install, AutoMigrate alone brings the
schema up to date — nothing here needs to run.

## What this directory actually is

These numbered `NNN_*.up.sql` / `NNN_*.down.sql` files are a legacy, hand-rolled
migration set predating AutoMigrate, retained for operators whose database was
originally bootstrapped from migrations `001`–`003` (before AutoMigrate existed) and
who want to trace, by hand, how the schema evolved from that point. They are:

- **Not invoked by anything in this repo.** No CI workflow, Dockerfile, `Makefile`
  target, or Go code path executes these files. `internal/cli/migrate/migrate.go` is
  an unrelated one-off data-migration CLI (`migrate user-to-machine`, ADR-023) — it
  does not read `migrations/*.sql`.
- **Executable only via a standalone script the operator must run manually**:
  `scripts/run_migrations.sh` shells out to the external `golang-migrate` CLI (not a
  project dependency — `go.mod` has no migration-runner library; the operator must
  install it themselves) and applies these files against a database in numeric
  order. This is the one path by which these files could actually run — use it only
  if you know you need it, and **back up your database first**.
- **Not exercised by any test.** There is no automated harness that applies or
  validates these files; changes to them are unverified beyond manual review /
  ad-hoc dry-runs.

## Before running anything in this directory

1. You almost certainly don't need to: AutoMigrate already handles the upgrade from
   any pre-existing schema, including one bootstrapped from `001`-`003`.
2. If you do run `scripts/run_migrations.sh` (or apply these files by hand), **take a
   full database backup first**. Several `*.down.sql` rollback files intentionally
   `DROP` tables/columns holding security-relevant data with no export step — see the
   warning comment at the top of each destructive down-migration
   (`002_rbac_enhancements.down.sql`, `004_add_auth_encryption.down.sql`,
   `005_secret_sharing.down.sql`). Rolling back is not free: it can permanently
   discard encrypted credentials, sharing/access-grant history, or the RBAC audit
   trail.
3. These files are dialect-inconsistent by construction (some are SQLite-only,
   `007`/`008` are deliberately dual-dialect, `004` mixes in MySQL-only syntax) — they
   were never executed end-to-end as a single unit against one database engine.
   Verify each statement against your actual database engine before applying.
