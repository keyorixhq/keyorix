- **INV-ADMIN-restore-no-plaintext-legacy-columns** A restore of an archive written before a
  credential column was encrypted at rest leaves no plaintext behind: backupfmt's
  `legacyColumns` carries the old column's value into the raw legacy column, and
  `finishRestore` runs the same encrypting backfill the server runs at startup
  (`MigrateNotificationChannelURLsToEncrypted` for `notification_channels.url`) with the
  restored keys before the restore reports success. Every other archive column the current
  model does not map is still refused. Why: #3452 — v0.95.x archives were refused outright,
  and loading them without the backfill would leave webhook bearer URLs in plaintext (and a
  later `admin backup` would drop them, since the model does not map the column). Guard:
  `server/admin/restore_v095_archive_test.go` (`TestAdminRestore_V0953Archive`, a real v0.95.3
  archive; the Postgres leg is pg-gated), `internal/backupfmt/legacy_columns_test.go`
  (`TestLegacyColumns_AreUnmappedFieldsOfTheirModel`,
  `TestLoadArchive_UnknownColumnBesideLegacyStillRefused`).
<!-- section: Backup and restore -->
