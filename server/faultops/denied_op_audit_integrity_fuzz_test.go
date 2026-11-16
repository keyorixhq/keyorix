// denied_op_audit_integrity_fuzz_test.go -- FUZZ-MECH M1-AUDIT (AUD1):
// audit-log TRUTHFULNESS for DENIED operations.
//
// FuzzMixedPrincipalAuthority (M1, mixed_principal_authority_fuzz_test.go)
// already drives random (principal, operation, target-project) triples that an
// INDEPENDENT reference model (modelVerdict) says must be DENIED, and asserts
// the denial took no effect on NON-audit state (EFFECT-WITHOUT-AUTHORITY). It
// deliberately EXCLUDES the AuditEvent table from that diff
// (hashExcluding(before, "AuditEvent")), so it says nothing about whether the
// denial is recorded in the audit log, or -- the compliance-critical case --
// whether it is wrongly recorded as a SUCCESS.
//
// This target closes exactly that gap, reusing M1's model and world verbatim:
// for every triple the model DENIES, after executing the op as the
// under-privileged principal, no NEW AuditEvent row may carry Success=true.
// A denied, no-effect action that leaves a "Success=true" audit row is a
// FALSE-SUCCESS audit: the trail certifies an unauthorized action as a
// completed one -- the same class as a false OK, and for an EU-first product a
// compliance defect in its own right.
//
// Soundness. The oracle is only asserted when the op genuinely took no effect
// on non-audit state (the same fact M1 proves). If non-audit state DID change,
// the op was not actually denied (model over-deny, or a real
// EFFECT-WITHOUT-AUTHORITY bug M1 owns); this target then skips with a specific
// reason rather than asserting on a case where a Success=true audit would be
// legitimate. Because M1 is an existing, passing target, every model-DENY
// triple it covers truly makes no non-audit change -- so a Success=true audit
// row for one of them genuinely records a success that did not happen.
//
// What this does NOT verify (stated so the green is not mistaken for more):
//   - It does not assert that a denial IS audited (Success=false row present):
//     Keyorix broadly does not audit authorization refusals today (census
//     below quantifies it) and that is a reviewed baseline, not a per-run
//     failure. The HARD oracle is only the no-false-SUCCESS direction, which
//     cannot false-positive.
//   - It does not cover gRPC/SCIM/CLI transports (M1's v1 op set is REST-only).
//   - It does not check actor/target fields of the (absent) denial record.
//   - It does not check retry/second-transport duplication (separate concern).
package faultops

import (
	"context"
	"fmt"
	"sort"
	"testing"
)

// newAuditRow is the subset of an audit_events row this oracle inspects.
type newAuditRow struct {
	ID          uint
	EventType   string
	Success     *bool
	UserID      *uint
	Description string
}

// newAuditRowsSince returns every audit_events row with id > sinceMaxID, in id
// order -- the rows the operation under test wrote, nothing from before it.
func newAuditRowsSince(w *faultWorld, sinceMaxID uint) []newAuditRow {
	var rows []newAuditRow
	w.db.Table("audit_events").
		Where("id > ?", sinceMaxID).
		Order("id asc").
		Select("id", "event_type", "success", "user_id", "description").
		Find(&rows)
	return rows
}

// FuzzDeniedOpAuditNeverSuccess is FUZZ-MECH M1-AUDIT. See the file doc comment
// for the model's provenance, the soundness gate, and what is not covered.
func FuzzDeniedOpAuditNeverSuccess(f *testing.F) {
	for p := range int(numPrincipalKinds) {
		for o := range m1Ops {
			f.Add([]byte{byte(p), byte(o), 0})
			f.Add([]byte{byte(p), byte(o), 1})
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		pIdx, opIdx, tp, ok := decodeMixedPrincipalFuzzInput(data)
		if !ok {
			t.Skip("input too short")
		}
		ctx := context.Background()

		w := newFaultWorld(t, nil)
		mw, err := buildM1World(ctx, w)
		if err != nil {
			t.Skipf("setup buildM1World itself errored — not an audit finding: %v", err)
		}
		principals, err := buildM1Principals(ctx, w, mw)
		if err != nil {
			t.Skipf("setup buildM1Principals itself errored — not an audit finding: %v", err)
		}

		p := principals[pIdx]
		op := m1Ops[opIdx]

		deny, ok := modelVerdict(p, op, mw, tp)
		if !ok || !deny {
			return // not asserted: a genuine ALLOW, or the model is not confident here
		}

		var state any
		if op.setup != nil {
			state, err = op.setup(ctx, w, mw, tp)
			if err != nil {
				t.Skipf("op setup itself errored — not an audit finding: %v", err)
			}
		}

		drainAllBackgroundGoroutines()
		before, err := snapshotDB(w.db)
		if err != nil {
			t.Fatalf("snapshotting pre-execute world: %v", err)
		}
		beforeMaxID := maxAuditEventID(w)

		var result opResult
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic escaped the transport layer entirely for %s as %s (proj=%d): %v",
						op.key, p.kind, tp, r)
				}
			}()
			result, err = op.execute(ctx, w, mw, p.token, tp, state)
		}()
		if err != nil {
			t.Skipf("execute returned a transport error (not an application error) for %s as %s: %v", op.key, p.kind, err)
		}

		drainAllBackgroundGoroutines()
		after, err := snapshotDB(w.db)
		if err != nil {
			t.Fatalf("snapshotting post-execute world: %v", err)
		}

		// Soundness gate: only assert the no-false-SUCCESS property when the op
		// genuinely took no effect on non-audit state. If it changed non-audit
		// state, it was not actually denied — that is EFFECT-WITHOUT-AUTHORITY,
		// owned by FuzzMixedPrincipalAuthority, and a Success=true audit would
		// then be legitimate, so this oracle is not sound to assert here.
		if hashExcluding(before, "AuditEvent") != hashExcluding(after, "AuditEvent") {
			t.Skipf("non-audit state changed for a model-DENY triple (%s as %s, proj=%d) — EFFECT-WITHOUT-AUTHORITY "+
				"is FuzzMixedPrincipalAuthority's to assert; this audit oracle is not sound here. Differing tables: %v",
				op.key, p.kind, tp, diffTables(before, after))
		}

		for _, row := range newAuditRowsSince(w, beforeMaxID) {
			if row.Success != nil && *row.Success {
				t.Errorf("FALSE-SUCCESS-AUDIT — %s as %s (targetProject=%d) was correctly denied and changed no "+
					"non-audit state (result=%+v), but wrote AuditEvent id=%d event_type=%q Success=true "+
					"(user_id=%v): the trail certifies an unauthorized action as a completed one.",
					op.key, p.kind, tp, result, row.ID, row.EventType, deref(row.UserID))
			}
		}
	})
}

func deref(p *uint) any {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// TestDeniedOpAuditCensus is the ground-truth census (not a pass/fail oracle):
// it runs every (principal, op, targetProject) triple the model DENIES exactly
// once, confirms the op took no non-audit effect, and tabulates the new
// AuditEvent rows it wrote by (event_type, success). This is how the
// no-false-SUCCESS oracle above was validated against what the system actually
// does, per "validate a mechanism against a failure that actually happened"
// (CLAUDE.md): it shows which denials are audited at all, and whether any
// legitimate Success=true row appears after a denied op (none may, or the hard
// oracle would be unsound).
func TestDeniedOpAuditCensus(t *testing.T) {
	if testing.Short() {
		t.Skip("census builds one full world per denied triple; skipped under -short")
	}
	ctx := context.Background()

	type cell struct {
		total        int
		audited      int // produced >=1 new audit row
		successRows  int // new rows with Success=true  (MUST be 0)
		failureRows  int // new rows with Success=false
		nilRows      int // new rows with Success nil
		effectLeaked int // non-audit state changed (should be 0; M1 owns it)
	}
	byEventTypeSuccess := map[string]int{}
	agg := cell{}

	for pIdx := range int(numPrincipalKinds) {
		for opIdx := range m1Ops {
			for tp := uint(0); tp < 2; tp++ {
				// Each case in its OWN subtest so its world DB closes when the
				// subtest ends (maxLiveWorldDBsPerTest, world_db_budget_test.go):
				// a flat loop on one t piles up every world until the test ends
				// and runs Postgres out of connection slots.
				t.Run(fmt.Sprintf("p%d/op%d/tp%d", pIdx, opIdx, tp), func(t *testing.T) {
					w := newFaultWorld(t, nil)
					mw, err := buildM1World(ctx, w)
					if err != nil {
						t.Skipf("buildM1World: %v", err)
					}
					principals, err := buildM1Principals(ctx, w, mw)
					if err != nil {
						t.Skipf("buildM1Principals: %v", err)
					}
					p := principals[pIdx]
					op := m1Ops[opIdx]
					deny, ok := modelVerdict(p, op, mw, tp)
					if !ok || !deny {
						t.Skip("not a model-DENY triple")
					}
					var state any
					if op.setup != nil {
						if state, err = op.setup(ctx, w, mw, tp); err != nil {
							t.Skipf("op setup: %v", err)
						}
					}
					drainAllBackgroundGoroutines()
					before, err := snapshotDB(w.db)
					if err != nil {
						t.Fatalf("snapshot before: %v", err)
					}
					beforeMaxID := maxAuditEventID(w)
					result, err := op.execute(ctx, w, mw, p.token, tp, state)
					if err != nil {
						t.Skipf("execute transport error: %v", err)
					}
					_ = result
					drainAllBackgroundGoroutines()
					after, err := snapshotDB(w.db)
					if err != nil {
						t.Fatalf("snapshot after: %v", err)
					}
					agg.total++
					if hashExcluding(before, "AuditEvent") != hashExcluding(after, "AuditEvent") {
						agg.effectLeaked++
					}
					rows := newAuditRowsSince(w, beforeMaxID)
					if len(rows) > 0 {
						agg.audited++
					}
					for _, r := range rows {
						switch {
						case r.Success == nil:
							agg.nilRows++
							byEventTypeSuccess[r.EventType+"|nil"]++
						case *r.Success:
							agg.successRows++
							byEventTypeSuccess[r.EventType+"|true"]++
						default:
							agg.failureRows++
							byEventTypeSuccess[r.EventType+"|false"]++
						}
					}
				})
			}
		}
	}

	t.Logf("DENIED-OP AUDIT CENSUS: %d denied triples; %d produced >=1 audit row; "+
		"successRows=%d failureRows=%d nilRows=%d; effectLeaked=%d",
		agg.total, agg.audited, agg.successRows, agg.failureRows, agg.nilRows, agg.effectLeaked)
	keys := make([]string, 0, len(byEventTypeSuccess))
	for k := range byEventTypeSuccess {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  audit row: event_type|success = %-48s count=%d", k, byEventTypeSuccess[k])
	}
	if agg.successRows != 0 {
		t.Logf("NOTE: %d Success=true audit rows appeared after denied ops — FuzzDeniedOpAuditNeverSuccess "+
			"will flag these as FALSE-SUCCESS-AUDIT.", agg.successRows)
	}
}

// TestDeniedOpAudit_NotVacuous proves the oracle's audit-row plumbing is live:
// for an ALLOWED op (admin creating a secret), a Success=true audit row DOES
// appear via newAuditRowsSince. If this ever stopped seeing the row, a green
// FuzzDeniedOpAuditNeverSuccess would be meaningless (every query returning
// nothing). This is the counterpart to M1's PositiveControls.
func TestDeniedOpAudit_NotVacuous(t *testing.T) {
	ctx := context.Background()
	w := newFaultWorld(t, nil)
	mw, err := buildM1World(ctx, w)
	if err != nil {
		t.Fatalf("buildM1World: %v", err)
	}
	principals, err := buildM1Principals(ctx, w, mw)
	if err != nil {
		t.Fatalf("buildM1Principals: %v", err)
	}
	var admin principalFixture
	for _, cand := range principals {
		if cand.kind == principalGlobalAdmin {
			admin = cand
		}
	}
	var createSecret m1Op
	for _, cand := range m1Ops {
		if cand.key == "REST POST /api/v1/secrets/" {
			createSecret = cand
		}
	}
	drainAllBackgroundGoroutines()
	beforeMaxID := maxAuditEventID(w)
	result, err := createSecret.execute(ctx, w, mw, admin.token, 0, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected admin secret-create to succeed, got %+v", result)
	}
	drainAllBackgroundGoroutines()
	var sawSuccess bool
	var seen []string
	for _, r := range newAuditRowsSince(w, beforeMaxID) {
		seen = append(seen, fmt.Sprintf("%s(success=%v)", r.EventType, boolPtr(r.Success)))
		if r.Success != nil && *r.Success {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Fatalf("expected a Success=true audit row after an allowed secret-create (the oracle's plumbing must be "+
			"able to see one, or its green is vacuous); saw rows: %v", seen)
	}
}

func boolPtr(p *bool) any {
	if p == nil {
		return "<nil>"
	}
	return *p
}
