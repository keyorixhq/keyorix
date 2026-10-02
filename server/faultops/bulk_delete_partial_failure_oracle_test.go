package faultops

import "testing"

// TestBulkPartialFailureAccountsForDiff is the red-proof for
// bulkPartialFailureAccountsForDiff (fuzz_storage_fault_operations_test.go):
// it must accept exactly the shape #2410 found (a single-item bulk-delete call
// that reports its only item as failed, with this run's final state
// byte-for-byte identical to its own pre-fault snapshot) and reject every
// mutation of that shape — including, per coordinator review, the case an
// earlier "diff confined to the tables a delete would touch" version of this
// check would have wrongly accepted: a bogus audit/access-log row written for
// an item the body itself reports as failed (before != after, even though
// every differing table would have been in that old allowed set).
func TestBulkPartialFailureAccountsForDiff(t *testing.T) {
	const op = "REST POST /api/v1/projects/{id}/secrets/bulk-delete"
	const singleFailureBody = `HTTP 200: {"success":true,"data":{"deleted":[],"failed":[{"secret_id":1,"name":"fuzz-secret-setup","error":"Secret not found: fault-fuzz injected failure"}],"total":1}}`

	tests := []struct {
		name       string
		op         string
		detail     string
		beforeHash string
		afterHash  string
		want       bool
	}{
		{
			name:       "real #2410 shape: before==after, accepted",
			op:         op,
			detail:     singleFailureBody,
			beforeHash: "h1",
			afterHash:  "h1",
			want:       true,
		},
		{
			name: "coordinator-flagged shape: a bogus audit/access-log row written for the " +
				"reported-failed item (before != after) — rejected even though the old " +
				"table-name-only check would have waved it through as \"confined to allowed tables\"",
			op:         op,
			detail:     singleFailureBody,
			beforeHash: "h1",
			afterHash:  "h2",
			want:       false,
		},
		{
			name:       "batch actually deleted something: rejected regardless of hash equality",
			op:         op,
			detail:     `HTTP 200: {"success":true,"data":{"deleted":[1],"failed":[{"secret_id":2,"name":"x","error":"boom"}],"total":2}}`,
			beforeHash: "h1",
			afterHash:  "h1",
			want:       false,
		},
		{
			name:       "nothing reported failed: rejected",
			op:         op,
			detail:     `HTTP 200: {"success":true,"data":{"deleted":[],"failed":[],"total":0}}`,
			beforeHash: "h1",
			afterHash:  "h1",
			want:       false,
		},
		{
			name:       "op not in the scoped allowlist: rejected",
			op:         "REST POST /api/v1/projects/{id}/secrets/bulk-rename",
			detail:     singleFailureBody,
			beforeHash: "h1",
			afterHash:  "h1",
			want:       false,
		},
		{
			name:       "unparseable body: rejected",
			op:         op,
			detail:     `HTTP 200: not json`,
			beforeHash: "h1",
			afterHash:  "h1",
			want:       false,
		},
		{
			name:       "no \": \" separator at all: rejected",
			op:         op,
			detail:     `garbage`,
			beforeHash: "h1",
			afterHash:  "h1",
			want:       false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := oracleInput{
				op:     tc.op,
				result: opResult{Detail: tc.detail},
				before: dbSnapshot{Hash: tc.beforeHash},
				after:  dbSnapshot{Hash: tc.afterHash},
			}
			got := bulkPartialFailureAccountsForDiff(in)
			if got != tc.want {
				t.Errorf("bulkPartialFailureAccountsForDiff(op=%q, before=%q, after=%q) = %v, want %v",
					tc.op, tc.beforeHash, tc.afterHash, got, tc.want)
			}
		})
	}
}
