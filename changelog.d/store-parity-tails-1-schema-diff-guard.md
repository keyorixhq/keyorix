### Changed
- **`admin verify-audit --pg-dsn` help now says not to point it at a live database.** The
  flag takes no lock, and a purge running during the walk can make a valid chain read
  BROKEN; use a detached copy. Pinned by `TestVerifyAudit_PGDSNHelp_WarnsAgainstALiveDatabase`.

### Testing
- **Schema-diff guard for the upgrade path.** `TestSchemaParity_FreshVsUpgrade_{SQLite,Postgres}`
  build a fresh AutoMigrate database and one upgraded from v0.93.0 through the real boot
  path, and compare tables, columns (type, nullability, default), indexes (name, columns,
  uniqueness) and triggers, with a commented allowlist whose stale entries fail. It
  reports the pre-#4100 missing `idx_break_glass_activations_reviewed_by` (#4091).
