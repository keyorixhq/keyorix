// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// #4716: with the audit append's outcome unknown (an error after the write took
	// effect, or the audit transaction's COMMIT acknowledgement lost) the audit row may
	// or may not be there, and IssueLease aborts the minted lease either way
	// (abortUnauditedLease closes the row: status, reason, revoked_at). The lease row
	// exists, closed, in every outcome, so it matches neither the pre-fault state nor the
	// reference's active lease; it is left out of oracle (d)'s comparison. The audit rows
	// are compared separately by the rest of oracle (d), as for every op.
	registerEffectThenErrorExclusion("post_dynamic_secrets_configs_id_issue_logauditevent", effectThenErrorExclusion{op: "REST POST /api/v1/dynamic-secrets/configs/{id}/issue", method: "LogAuditEvent", tables: []string{"DynamicSecretLease"}})
}
