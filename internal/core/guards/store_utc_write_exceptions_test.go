package guards

// Rows for TestEveryStoreTimeColumnWriteIsUTC (store_utc_write_guard_test.go).

func init() {
	// Owned by another session: not scanned here, and not edited by UTC-STORE-SCAN-1.
	registerStoreScanSkip("local_break_glass.go",
		"UTC-SOLEWRITER-TAILS-1 #3914: break-glass cutoffs and writers move to the sole writer; its map writes already carry .UTC() today")

	// The audit write path in internal/storage/store is OPT-AUDIT-RT-1's. anchoredAt is the
	// anchor provider's asserted time (core/audit_checkpoint.go passes rec.Time as the provider
	// returned it); the column is only read back into API responses (handlers/audit.go applies
	// .UTC()), never compared in SQL, so a wrong zone cannot move a cutoff, but on SQLite it can
	// stop the checkpoint row scanning back. Fix (anchoredAt.UTC() at the write) is a LEFTOVER
	// for after OPT-AUDIT-RT-1 merges.
	registerStoreTimeWriteException("local_audit_checkpoint.go:UpdateAuditCheckpointAnchor:anchored_at",
		"OPT-AUDIT-RT-1 owns the audit write path; one-line .UTC() fix is a LEFTOVER of UTC-STORE-SCAN-1")
}
