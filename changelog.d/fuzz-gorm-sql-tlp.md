### Testing
- **SQLancer-style logic-bug fuzzing of the GORM data layer (task SQ1).** New
  `internal/storage/sqllogicfuzz` package with four Fuzz targets driving the
  production modernc-SQLite dialector and PostgreSQL: `FuzzTLP` (Ternary Logic
  Partitioning), `FuzzNoREC` (optimised vs un-optimised count), `FuzzCrossDialect`
  (same GORM query over a defined common subset on SQLite vs PostgreSQL —
  skips cleanly without `KEYORIX_TEST_PG_DSN`, creates/drops a `sq1_<pid>`
  database) and `FuzzGormInjectionStructure` (a bind-parameter value, including
  SQL-injection payloads, never changes the prepared-statement text). Each
  oracle has a committed red/green proof. Targets registered under
  `scripts/fuzzing/targets.d/`.
