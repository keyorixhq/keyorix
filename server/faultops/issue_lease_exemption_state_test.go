package faultops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// TestIssueLeaseExemption_ActiveLeaseRowStillFlagged pins the scope of the four
// IssueLease LogAuditEvent rows (#4716, REVIEW-4745-DEEP-1 F1): they accept the
// closed lease row abortUnauditedLease leaves, not any DynamicSecretLease content.
// Each case is driven through the real harness; the real state must pass, and the
// same state with the lease row left `active` (a minted credential nobody received)
// must be reported. The success-branch case checks that a SUCCESS whose lease row
// diverges from the reference is not exempted either (errorBranchOnly).
func TestIssueLeaseExemption_ActiveLeaseRowStillFlagged(t *testing.T) {
	noop := func() func() { return func() {} }
	for _, op := range []string{
		"REST POST /api/v1/dynamic-secrets/configs/{id}/issue",
		"GRPC keyorix.v1.DynamicSecretService.IssueLease",
	} {
		for _, kind := range []faultstorage.FaultKind{faultstorage.KindEffectThenError, faultstorage.KindError} {
			t.Run(op+"/"+kind.String(), func(t *testing.T) {
				in, outcome, reason := driveFaultCase(t, op, "LogAuditEvent", 1, kind)
				if outcome != driveObserved {
					t.Fatalf("case could not be driven (%s: %s)", outcome, reason)
				}
				if in.result.Success {
					t.Fatalf("the faulted issue reported success, the #4716 abort did not run: %s", in.result.Detail)
				}
				if f := oracleFindingsWithout(t, in, noop); len(f) > 0 {
					t.Fatalf("the real abort state is reported: %v", f)
				}

				active := in
				active.after = withLeaseRowsActive(t, in.before, in.after)
				if f := oracleFindingsWithout(t, active, noop); len(f) == 0 {
					t.Fatal("a failed issue that left its lease row active is accepted by design")
				} else {
					t.Logf("active lease row flagged: %s", f[0])
				}

				if kind == faultstorage.KindError {
					success := in
					success.result.Success = true
					if f := oracleFindingsWithout(t, success, noop); len(f) == 0 {
						t.Fatal("a SUCCESS whose lease row differs from the reference is accepted by design")
					}
				}
			})
		}
	}
}

// withLeaseRowsActive returns after with every DynamicSecretLease row the request
// wrote set back to `active` (no revoke reason), table and snapshot hashes rebuilt.
func withLeaseRowsActive(t *testing.T, before, after dbSnapshot) dbSnapshot {
	t.Helper()
	const table = "DynamicSecretLease"
	ts := after.Tables[table]
	rows := make([]string, 0, len(ts.Rows))
	flipped := 0
	for _, row := range ts.Rows {
		if slices.Contains(before.Tables[table].Rows, row) {
			rows = append(rows, row)
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(row), &fields); err != nil {
			t.Fatalf("lease row %s: %v", row, err)
		}
		fields["Status"] = json.RawMessage(`"active"`)
		fields["RevokeReason"] = json.RawMessage(`""`)
		b, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, string(b))
		flipped++
	}
	if flipped == 0 {
		t.Fatal("the faulted issue wrote no lease row: the case does not reach the abort")
	}
	sort.Strings(rows)
	out := dbSnapshot{Tables: maps.Clone(after.Tables)}
	h := sha256.Sum256([]byte(strings.Join(rows, "\n"))) // snapshotDB's table hash
	out.Tables[table] = tableSnapshot{Table: table, Rows: rows, Hash: hex.EncodeToString(h[:])}
	out.Hash = hashExcluding(out)
	return out
}
