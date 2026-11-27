// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// The gRPC twin of post_dynamic_secrets_configs_id_issue_logauditevent (#4716).
	registerOpScopedBestEffort("grpc_dynamicsecretservice_issuelease_logauditevent", opScopedBestEffortTable{op: "GRPC keyorix.v1.DynamicSecretService.IssueLease", method: "LogAuditEvent", tables: []string{"DynamicSecretLease", "AuditEvent"}, errorBranchOnly: true, acceptState: issueLeaseAbortedState})
}
