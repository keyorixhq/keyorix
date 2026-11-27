// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// BREAKGLASS-OWED-1 (internal/core/break_glass.go, activateBreakGlassDegraded):
	// when the activation's audit append is refused, the activation still commits,
	// degraded, with its audit rows owed in pending_audit_events and a notification
	// for the reviewers. Against the fault-free reference that is exactly
	// BreakGlassActivation + PendingAuditEvent + Notification + AuditEvent, and it is
	// the documented design, not a partial commit
	// (TestBreakGlassActivation_AuditFailure_CommitsDegradedWithOwedRecords asserts
	// the same shape for a method-level fault). Found by FuzzIOFaultOperations: ENOSPC
	// on the audit_events INSERT of the activation. requireLogSubstring ties the
	// exemption to the degraded path's own SECURITY log line, so a diff of this shape
	// without that evidence stays a violation.
	registerOpScopedBestEffort("post_projects_id_break_glass_logauditevent", opScopedBestEffortTable{
		op: "REST POST /api/v1/projects/{id}/break-glass", method: "LogAuditEvent",
		tables:              []string{"AuditEvent", "BreakGlassActivation", "Notification", "PendingAuditEvent"},
		requireLogSubstring: "is DEGRADED: user",
	})
}
