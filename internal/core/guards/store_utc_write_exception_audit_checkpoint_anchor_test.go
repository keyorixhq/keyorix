package guards

func init() {
	registerStoreTimeWriteException("local_audit_checkpoint.go:UpdateAuditCheckpointAnchor:anchored_at",
		"NOT safe on SQLite: anchoredAt is the anchor provider's asserted time as core/audit_checkpoint.go received it. The column is only read "+
			"back into API responses (.UTC() applied there), never compared in SQL, so no cutoff moves, but a non-UTC value can stop the "+
			"checkpoint row scanning back. The audit write path is OPT-AUDIT-RT-1's; the one-line anchoredAt.UTC() fix is a LEFTOVER of "+
			"UTC-STORE-SCAN-1. Remove this file with the fix")
}
