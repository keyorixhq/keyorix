- **INV-ADMIN-backup-refuses-unmigrated-legacy-url** `admin backup` never archives a database in which a
  notification channel's webhook URL exists only in the plaintext legacy `notification_channels.url` column
  (a database upgraded in place from v0.95.x, backed up before the new server's first start ran
  `MigrateNotificationChannelURLsToEncrypted`): it refuses, before the archive file is created, with
  "start the server once to finish the upgrade migrations, then back up". The writer maps only the
  current model's columns, so archiving such a row would drop the URL silently; carrying it would put the
  plaintext in the archive (or need the DEK, which a live server holds). Why: ABT-1, follow-up of #3807.
  Guard: `server/admin/backup_inplace_legacy_url_test.go`
  (`TestAdminBackup_InPlaceUpgradeBeforeFirstStart_NeverDropsTheURL`,
  `TestAdminBackup_InPlaceUpgradeAfterFirstStart_CarriesTheURL`; the Postgres legs are pg-gated).
<!-- section: Backup and restore -->
