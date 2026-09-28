// audit_completeness_fuzz_test.go -- FUZZ-MECH M6: audit-completeness
// invariant. Reuses the shared fault-injection op catalog (opcatalog_test.go,
// FAULTOPS-SPEED-owned, read-only reuse -- this file adds no changes to it)
// and world/snapshot infra to check, for each catalog operation run WITHOUT
// any fault armed:
//
//  1. A successful call writes AT LEAST one new AuditEvent (never zero) --
//     never silently un-audited.
//  2. Every NEW AuditEvent row's Success field matches the operation's own
//     observed result (Success on a successful call, Success=false on a
//     failed one) -- an audit trail that disagrees with what actually
//     happened is worse than none (it certifies the wrong thing).
//  3. The audit hash chain (core.VerifyAuditChain) always verifies
//     afterward, success or failure.
//
// "Exactly one" (the track item's own stronger phrasing) is deliberately
// NOT asserted as a hard upper bound: several opCatalog operations are
// compound at the business-logic layer (e.g. a role assignment that also
// triggers a permission-baseline recompute event) and legitimately write
// more than one row for a single caller-visible action -- asserting an
// exact count would either force this harness to hardcode a per-operation
// expected count (fragile, drifts the moment FAULTOPS-SPEED wires a new
// operation with different audit shape) or produce false positives on
// correct, already-reviewed behavior. The lower bound (at least one, never
// zero) and the Success-field agreement are the two properties that are
// both sound (assert only the non-false-positive direction) and actually
// catch the failure class this item is about: a mutating call that leaves
// no trace, or a trail that lies about what happened.
//
// FINDING (2026-09-27, docs/findings/2026-09-27-FINDING-audit-completeness-baseline-gap.md):
// this fuzzer's first run against the (now 192-operation) opCatalog found
// 62 operations that succeed with NO audit trail at all -- spot-verified by
// reading core.DeleteProject directly: it writes an audit event only on a
// specific dynamic-secret-cascade FAILURE path, never on the deletion
// itself succeeding. Filed NEEDS ANDREI (see the finding doc) rather than
// fixed here: 62 call sites across many subsystems is a scope/priority
// decision, not a small, obvious, single-PR fix. knownUnauditedOperations
// below is the reviewed, dated baseline this harness ratchets against --
// any operation NOT in this map is asserted on unconditionally, so a new
// gap introduced after this baseline fails immediately.
package faultops

import (
	"context"
	"testing"
)

// knownUnauditedOperations is the reviewed baseline of opCatalog operations
// confirmed (2026-09-27) to succeed with no audit trail. Every entry is a
// tracked, NOT-fixed gap -- being listed here is not a claim of safety, it
// is what stops this harness from failing on a large, pre-existing baseline
// while still catching any NEW unaudited operation immediately. Shrink this
// map, never grow it silently: removing an entry (because someone wired
// audit logging for it) is the harness improving; adding one here instead
// of fixing the gap defeats the harness's purpose and must be reasoned
// about explicitly, not done by habit.
var knownUnauditedOperations = map[string]bool{
	// ── Still unaudited, out of F5's scope (tracked gaps; F1-F4's entries were
	// removed by their own PRs, all merged before this rebase on 2026-09-30).
	"REST POST /api/v1/projects":     true,
	"REST POST /api/v1/users/":       true,
	"REST PUT /api/v1/auth/profile":  true,
	"REST PUT /api/v1/projects/{id}": true,
	"REST PUT /api/v1/users/{id}":    true,

	// ── Confirmed intentional (F5, 2026-09-28): reviewed and judged NOT
	// security-relevant, or already covered by a narrower audit trail than the
	// fuzzer's opCatalog call happens to exercise. Each reason is specific to
	// the operation, not a blanket "low priority".
	//
	// A dry run computes and returns its result WITHOUT persisting anything
	// (see MigrateAuditChainEncoding's doc comment) -- TestMigrateAuditChainEncoding_
	// Core_DryRunPersistsNothing already asserts zero completion events after a
	// dry run. Only a REAL run (dryRun=false) appends one, and that path is
	// already audited.
	"REST POST /api/v1/audit/migrate-chain-encoding": true,
	// Marking one's own notification read/all-read is personal UI state with no
	// security-relevant effect (no access, permission, or credential changes) --
	// not comparable to the access-control and secret-lifecycle events this
	// fuzzer otherwise enforces.
	"REST POST /api/v1/notifications/{id}/read": true,
	"REST POST /api/v1/notifications/read-all":  true,
	// RenderSecretTemplate DOES audit each resolved secret reference as a
	// secret.read event (see commitStagedSecretRead) -- a bulk render is not a
	// silent exfiltration channel. A template with zero secret references
	// resolves nothing and has nothing to audit; that's the branch the fuzzer's
	// generic opCatalog call exercises.
	"REST POST /api/v1/projects/{id}/secrets/render": true,
	// SimulateRotation is a pure read-only validation/diagnostic: it never
	// mutates state and doesn't even accept an actor parameter, unlike every
	// other operation in this map.
	"REST POST /api/v1/secrets/{id}/rotation/simulate": true,
	// The security-relevant branch (a rotated-away refresh token presented
	// again -- a possible theft/replay indicator) IS already audited via
	// EventSessionReuseDetected (handleSessionReuse). An ordinary successful
	// refresh is a high-volume, self-service, non-privilege-changing operation
	// -- consistent with this codebase's existing convention that a successful
	// login itself is not audited either.
	"REST POST /auth/refresh": true,
	// A real password-reset request for an existing, resettable account IS
	// already audited (deliverSetupLink records the delivery). Requests for a
	// nonexistent, blocked, or externally-managed (SSO/SCIM) account return the
	// identical response by deliberate anti-enumeration design
	// (RequestPasswordReset) and are silent by construction; abuse patterns on
	// those are tracked via the separate per-IP rate limiter
	// (RecordPasswordResetAttempt), not the audit log.
	"REST POST /auth/password-reset": true,
}

func auditEventCount(w *faultWorld) int64 {
	var count int64
	w.db.Table("audit_events").Count(&count)
	return int64(count)
}

// newestAuditEventsSuccessField returns the Success field of every AuditEvent
// row with id > sinceMaxID, in id order -- the rows this operation's own
// call wrote, nothing from before it.
func newestAuditEventsSuccessField(w *faultWorld, sinceMaxID uint) []*bool {
	var rows []struct {
		ID      uint
		Success *bool
	}
	w.db.Table("audit_events").Where("id > ?", sinceMaxID).Order("id asc").Find(&rows)
	out := make([]*bool, len(rows))
	for i, r := range rows {
		out[i] = r.Success
	}
	return out
}

func maxAuditEventID(w *faultWorld) uint {
	var maxID uint
	w.db.Table("audit_events").Select("COALESCE(MAX(id), 0)").Scan(&maxID)
	return maxID
}

// FuzzAuditCompleteness is FUZZ-MECH M6. See the package doc comment above
// for the exact properties asserted and why "exactly one" is not one of them.
func FuzzAuditCompleteness(f *testing.F) {
	for i := range opCatalog {
		f.Add(uint8(i))
	}

	f.Fuzz(func(t *testing.T, sel uint8) {
		op := opCatalog[int(sel)%len(opCatalog)]
		ctx := context.Background()
		w := newFaultWorld(t, nil) // no fault armed -- this item is about audit completeness, not fault injection

		var state any
		var err error
		if op.Setup != nil {
			state, err = op.Setup(ctx, w)
			if err != nil {
				t.Skipf("op setup itself errored — not an audit-completeness finding: %v", err)
			}
		}

		drainAllBackgroundGoroutines()
		beforeMaxID := maxAuditEventID(w)
		beforeCount := auditEventCount(w)

		result, err := op.Execute(ctx, w, state)
		if err != nil {
			t.Skipf("execute returned a transport error (not an application error) for %s: %v", op.Key, err)
		}

		drainAllBackgroundGoroutines()
		afterCount := auditEventCount(w)

		// Oracle 1: a successful call never writes zero audit events --
		// except the reviewed, tracked entries in knownUnauditedOperations
		// (see its own doc comment). A key NOT in that map is asserted on
		// unconditionally, so any operation FAULTOPS-SPEED wires into
		// opCatalog in the future that turns out unaudited fails this
		// harness immediately, rather than silently joining an
		// ever-growing, unreviewed gap.
		if result.Success && afterCount == beforeCount {
			if _, known := knownUnauditedOperations[op.Key]; !known {
				t.Errorf("AUDIT-COMPLETENESS VIOLATION — %s succeeded (result=%+v) but wrote NO new AuditEvent row",
					op.Key, result)
			}
		}

		// Oracle 2: every new row's Success field agrees with what actually
		// happened -- an audit trail that certifies the wrong outcome is
		// worse than a missing one (oracle 1 already covers "missing").
		for i, success := range newestAuditEventsSuccessField(w, beforeMaxID) {
			if success == nil {
				continue // Success defaults to true at the DB level (gorm:"default:true") but a nil pointer here just means "not set on this row" -- not itself a finding this oracle is sound to assert on, since some event types are documented as attribution-only, not outcome-carrying.
			}
			if *success != result.Success {
				t.Errorf("AUDIT-COMPLETENESS VIOLATION — %s actually %s (result=%+v), but new AuditEvent row #%d recorded Success=%v",
					op.Key, map[bool]string{true: "succeeded", false: "failed"}[result.Success], result, i, *success)
			}
		}

		// Oracle 3: the audit hash chain always verifies, success or failure.
		verification, err := w.core.VerifyAuditChain(ctx)
		if err != nil {
			t.Fatalf("VerifyAuditChain after %s: %v", op.Key, err)
		}
		if !verification.Valid {
			t.Errorf("AUDIT-COMPLETENESS VIOLATION — audit chain failed to verify after %s: first broken id=%v (chained=%d, unchained=%d)",
				op.Key, verification.FirstBrokenID, verification.ChainedEvents, verification.UnchainedEvents)
		}
	})
}

// TestKnownUnauditedOperationsAreRealCatalogKeys fails if
// knownUnauditedOperations names a key that isn't (or is no longer) in
// opCatalog -- a typo or a renamed operation would otherwise silently do
// nothing (the entry just never matches, so the harness quietly asserts
// unconditionally on a DIFFERENT operation than the one that was actually
// reviewed and excluded), the same drift class TestOperationCatalogKeysAreRegistered
// (opcatalog_test.go) guards against for the catalog itself.
func TestKnownUnauditedOperationsAreRealCatalogKeys(t *testing.T) {
	inCatalog := make(map[string]bool, len(opCatalog))
	for _, op := range opCatalog {
		inCatalog[op.Key] = true
	}
	for key := range knownUnauditedOperations {
		if !inCatalog[key] {
			t.Errorf("knownUnauditedOperations names %q, which is not (or no longer) an opCatalog key -- "+
				"stale entry, fix or remove it", key)
		}
	}
}

// TestAuditCompletenessCoverage reports the current audited/pending split --
// informational, not a completeness claim. The floor is a shrink-tripwire:
// opCatalog growing without a corresponding update here would otherwise let
// the pending baseline silently drift stale in the other direction (looking
// smaller, relative to the catalog, than it really is).
func TestAuditCompletenessCoverage(t *testing.T) {
	const minCatalogPopulation = 190
	if len(opCatalog) < minCatalogPopulation {
		t.Fatalf("opCatalog shrank to %d entries (floor %d) — has this test's own assumptions about the "+
			"catalog's shape silently gone stale?", len(opCatalog), minCatalogPopulation)
	}
	t.Logf("audit-completeness: %d of %d opCatalog operations currently unaudited on success (tracked, NOT fixed -- see docs/findings/2026-09-27-FINDING-audit-completeness-baseline-gap.md)",
		len(knownUnauditedOperations), len(opCatalog))
}
