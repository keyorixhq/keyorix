package admin

func init() {
	registerBackupUnmappedColumn("notification_channels", "url",
		"legacy: the plaintext webhook URL column of v0.95.x, encrypted into url_enc/url_meta by the server's startup backfill "+
			"(MigrateNotificationChannelURLsToEncrypted) and by restore for an older archive (backupfmt legacyColumns); "+
			"a backup refuses while it still holds a URL (INV-ADMIN-backup-refuses-unmigrated-legacy-url)")
}
