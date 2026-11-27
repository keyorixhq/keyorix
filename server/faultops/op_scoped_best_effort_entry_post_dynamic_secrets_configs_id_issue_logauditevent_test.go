// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #4716 audit-before-disclosure (IssueLease, internal/core/dynamic_secrets.go): the
	// mint and the lease row precede the dynamic_lease.issued audit event, so when that
	// event is not recorded IssueLease aborts the lease (abortUnauditedLease: the
	// credential is revoked on the target and the row closed) and returns an error.
	// The failed request therefore leaves a closed lease row, by design; the credential
	// is never returned. Found by FuzzIOFaultOperations on the audit transaction's
	// statements and COMMIT (the pool attributes both to LogAuditEvent).
	registerOpScopedBestEffort("post_dynamic_secrets_configs_id_issue_logauditevent", opScopedBestEffortTable{op: "REST POST /api/v1/dynamic-secrets/configs/{id}/issue", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}, errorBranchOnly: true, acceptState: issueLeaseAbortedState, pinnedKinds: []faultstorage.FaultKind{faultstorage.KindError}})
}
