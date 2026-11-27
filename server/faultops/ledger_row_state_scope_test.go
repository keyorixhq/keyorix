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
				active.after = withChangedRowsSet(t, in.before, in.after, "DynamicSecretLease",
					map[string]string{"Status": `"active"`, "RevokeReason": `""`})
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

// withChangedRowsSet returns after with set (column -> raw JSON value) applied to
// every row of table the request wrote, table and snapshot hashes rebuilt.
func withChangedRowsSet(t *testing.T, before, after dbSnapshot, table string, set map[string]string) dbSnapshot {
	t.Helper()
	ts := after.Tables[table]
	rows := make([]string, 0, len(ts.Rows))
	changed := 0
	for _, row := range ts.Rows {
		if slices.Contains(before.Tables[table].Rows, row) {
			rows = append(rows, row)
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(row), &fields); err != nil {
			t.Fatalf("%s row %s: %v", table, row, err)
		}
		for col, v := range set {
			fields[col] = json.RawMessage(v)
		}
		b, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, string(b))
		changed++
	}
	if changed == 0 {
		t.Fatalf("the faulted request wrote no %s row: the case does not reach the documented path", table)
	}
	sort.Strings(rows)
	out := dbSnapshot{Tables: maps.Clone(after.Tables)}
	h := sha256.Sum256([]byte(strings.Join(rows, "\n"))) // snapshotDB's table hash
	out.Tables[table] = tableSnapshot{Table: table, Rows: rows, Hash: hex.EncodeToString(h[:])}
	out.Hash = hashExcluding(out)
	return out
}

// TestAccessReviewCampaignExemption_UndegradedRowStillFlagged pins the scope of the
// ROLE-SHAPE-1 access-review rows (REVIEW-4745-DEEP-1 L2): they accept the campaign
// row that carries the degraded report, not any AccessReviewCampaign diff. Driven on
// the two pinned methods; GetEnvironment and ListRoles are not drivable here.
func TestAccessReviewCampaignExemption_UndegradedRowStillFlagged(t *testing.T) {
	noop := func() func() { return func() {} }
	const op = "REST POST /api/v1/projects/{id}/access-review/campaigns"
	for _, method := range []string{"ListAllUserRoleGrants", "ListAllGroupRoleGrants"} {
		t.Run(method, func(t *testing.T) {
			in, outcome, reason := driveFaultCase(t, op, method, 1, faultstorage.KindError)
			if outcome != driveObserved {
				t.Fatalf("case could not be driven (%s: %s)", outcome, reason)
			}
			if f := oracleFindingsWithout(t, in, noop); len(f) > 0 {
				t.Fatalf("the real degraded state is reported: %v", f)
			}
			// A lost Degraded flag alone matches the reference; the row must also
			// diverge in another column (ForcedIncomplete) for the exemption to matter.
			undegraded := in
			undegraded.after = withChangedRowsSet(t, in.before, in.after, "AccessReviewCampaign",
				map[string]string{"Degraded": `false`, "DegradedReasons": `null`, "ForcedIncomplete": `true`})
			if f := oracleFindingsWithout(t, undegraded, noop); len(f) == 0 {
				t.Fatal("a campaign row that diverges without the degraded report is accepted by design")
			} else {
				t.Logf("undegraded campaign row flagged: %s", f[0])
			}
		})
	}
}
