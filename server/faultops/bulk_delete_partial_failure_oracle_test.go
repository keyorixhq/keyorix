package faultops

import "testing"

// TestBulkPartialFailureAccountsForDiff is the red-proof for
// bulkPartialFailureAccountsForDiff (fuzz_storage_fault_operations_test.go):
// it must accept exactly the shape #2410 found (a single-item bulk-delete
// call that reports its only item as failed, with the diff confined to the
// tables a delete would have touched) and reject every mutation of that
// shape — an unexplained extra table, a batch that actually deleted
// something, a body with nothing reported failed, an op this exemption isn't
// scoped to, or a body that doesn't parse.
func TestBulkPartialFailureAccountsForDiff(t *testing.T) {
	const op = "REST POST /api/v1/projects/{id}/secrets/bulk-delete"
	const singleFailureBody = `HTTP 200: {"success":true,"data":{"deleted":[],"failed":[{"secret_id":1,"name":"fuzz-secret-setup","error":"Secret not found: fault-fuzz injected failure"}],"total":1}}`

	tests := []struct {
		name   string
		op     string
		detail string
		diff   []string
		want   bool
	}{
		{
			name:   "real #2410 shape: accepted",
			op:     op,
			detail: singleFailureBody,
			diff:   []string{"AuditEvent", "SecretAccessLog", "SecretNode"},
			want:   true,
		},
		{
			name:   "subset of the allowed tables: still accepted",
			op:     op,
			detail: singleFailureBody,
			diff:   []string{"SecretNode"},
			want:   true,
		},
		{
			name:   "unexplained extra table: rejected",
			op:     op,
			detail: singleFailureBody,
			diff:   []string{"AuditEvent", "SecretAccessLog", "SecretNode", "UserRole"},
			want:   false,
		},
		{
			name:   "batch actually deleted something: rejected",
			op:     op,
			detail: `HTTP 200: {"success":true,"data":{"deleted":[1],"failed":[{"secret_id":2,"name":"x","error":"boom"}],"total":2}}`,
			diff:   []string{"SecretNode"},
			want:   false,
		},
		{
			name:   "nothing reported failed: rejected",
			op:     op,
			detail: `HTTP 200: {"success":true,"data":{"deleted":[],"failed":[],"total":0}}`,
			diff:   []string{"SecretNode"},
			want:   false,
		},
		{
			name:   "op not in the scoped allowlist: rejected",
			op:     "REST POST /api/v1/projects/{id}/secrets/bulk-rename",
			detail: singleFailureBody,
			diff:   []string{"SecretNode"},
			want:   false,
		},
		{
			name:   "unparseable body: rejected",
			op:     op,
			detail: `HTTP 200: not json`,
			diff:   []string{"SecretNode"},
			want:   false,
		},
		{
			name:   "no \": \" separator at all: rejected",
			op:     op,
			detail: `garbage`,
			diff:   []string{"SecretNode"},
			want:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := bulkPartialFailureAccountsForDiff(tc.op, tc.detail, tc.diff)
			if got != tc.want {
				t.Errorf("bulkPartialFailureAccountsForDiff(%q, ..., %v) = %v, want %v", tc.op, tc.diff, got, tc.want)
			}
		})
	}
}
