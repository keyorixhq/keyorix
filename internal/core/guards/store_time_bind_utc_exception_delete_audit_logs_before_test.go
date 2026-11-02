package guards

func init() {
	registerStoreTimeBindException("local_audit.go:DeleteAuditLogsBefore:event_time",
		"NOT safe: known open host-zone bind (#3914), audit family, owned by the audit sessions (OPT-AUDIT-RT-1) "+
			"and left out of #3921 on purpose; remove this file when #3914's audit part is fixed")
}
