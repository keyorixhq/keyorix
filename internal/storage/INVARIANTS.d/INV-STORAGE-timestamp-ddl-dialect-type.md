- **INV-STORAGE-timestamp-ddl-dialect-type** Every hand-written DDL statement in `migrateDatabase`
  that adds or recreates a column a model maps to `time.Time` / `*time.Time` declares the dialect's own
  type through `sqlTimestampType(db)` (`DATETIME` on SQLite, `TIMESTAMP WITH TIME ZONE` on
  PostgreSQL) or goes through `Migrator().AddColumn`. Why (#3440, OTP-EXPIRY-1): SQLite accepts a
  literal `TIMESTAMP WITH TIME ZONE`, but the driver then returns stored values as strings, and every
  read of the row through the model fails with "unsupported Scan, storing driver.Value type string
  into type *time.Time". Guard: `internal/storage` `TestNoHandWrittenTimestampColumnDDL` (string
  literals in non-test code under `internal/storage`; red on origin/main a73f23733 at the 15
  literal sites, matcher pinned by `TestHandWrittenTimestampType_Matcher`) and
  `TestTimestampAlters_SQLite_ReadBackThroughModel` (each such column dropped, re-added by the upgrade,
  written and read back through the model; red on the same base for the 10 literal-type columns).
  `TestTimestampAlters_SupportedUpgradeSources_NoUnscannableColumn` pins that the v093/v094/v095
  upgrade fixtures have no such column before or after the upgrade. **Not covered**: SQL outside
  `internal/storage` and a type assembled at run time from non-literal parts.
