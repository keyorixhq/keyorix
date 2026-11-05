package guards

// utc_time_write_exceptions_test.go -- the rows of timeWriteExceptions (GUARD-PROMOTE-2 item 3),
// one registerTimeWriteException call each. Every row was checked on the real write path on
// 2026-11-04; the scan is shape-based, so it cannot see these two kinds of safety.
func init() {
	// The model has a BeforeSave hook that normalises the field, and the value is saved through it.
	registerTimeWriteException("auth.go:capSetupSession:ExpiresAt",
		"models.Session.BeforeSave normalises ExpiresAt; the value is a copy of the ceiling that capSetupSession just made UTC")

	// The column is written elsewhere and made UTC there; this line only mirrors it in memory.
	registerTimeWriteException("secrets.go:applyUpdateSecretFields:Expiration",
		"in-memory only; the column is written by UpdateSecretFields, which does f.Expiration.UTC() (local_secrets.go)")
	registerTimeWriteException("sharing.go:UpdateSharePermission:ExpiresAt",
		"UpdateShareRecord writes a map (no hook) after share.ExpiresAt.UTC() (local_sharing.go)")
}
