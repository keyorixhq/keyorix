package guards

// utc_time_write_exceptions_test.go -- the rows of timeWriteExceptions (GUARD-PROMOTE-2 item 3),
// one registerTimeWriteException call each. Every row was checked on the real write path on
// 2026-11-04; the scan is shape-based, so it cannot see these three kinds of safety.
func init() {
	// The model has a BeforeSave hook that normalises the field, and the value is saved through it.
	registerTimeWriteException("auth.go:capSetupSession:ExpiresAt",
		"models.Session.BeforeSave normalises ExpiresAt; the value is a copy of the ceiling that capSetupSession just made UTC")
	registerTimeWriteException("secrets.go:applyUpdateSecretFields:Expiration",
		"models.SecretNode.BeforeSave normalises Expiration when UpdateSecret saves the node")
	registerTimeWriteException("sharing.go:UpdateSharePermission:ExpiresAt",
		"models.ShareRecord.BeforeSave normalises ExpiresAt when UpdateShareRecord saves the copy")

	// The column is written elsewhere and made UTC there; this line only mirrors it in memory.
	registerTimeWriteException("secrets.go:secretFieldUpdateFromRequest:Expiration",
		"builds a storage.SecretFieldUpdate; LocalStorage.UpdateSecretFields does f.Expiration.UTC() before the column write (local_secrets.go)")
	registerTimeWriteException("secret_extend_expiring.go:ExtendExpiringSecrets:Expiration",
		"in-memory mirror of a value UpdateSecretFields already stored as UTC; the struct is not saved again")
	registerTimeWriteException("dynamic_secrets.go:RenewLease:ExpiresAt",
		"in-memory mirror of a value ExtendDynamicSecretLeaseExpiry already stored as newExpiry.UTC(); the struct is not saved again")

	// Not a database column at all.
	registerTimeWriteException("access_review.go:annotateLastUsedAt:LastUsedAt",
		"core.AccessReviewEntry is a report DTO serialised as JSON, not a gorm model or a time column")
}
