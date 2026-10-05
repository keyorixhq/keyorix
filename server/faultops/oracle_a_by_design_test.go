// oracle_a_by_design_test.go — #2549: the acceptable-by-design exemption
// oracle (a)'s error-reporting branch was missing, plus the staleness guard
// that would have caught four of #2549's own tolerances going dead.
//
// What #2549 asked for, and what was actually still missing
// ---------------------------------------------------------
// The issue reports that checkOracles' oracle (a) SUCCESS branch has
// onlyOutcomeLogTables (accept an AuditEvent-only diff unconditionally, safe
// because oracle (c) already ruled out the fail-open authz cause) while "the
// `default:` (error-reporting) branch has no equivalent exemption."
//
// That is no longer true: the error branch grew its own onlyOutcomeLogTables
// check. Driving #2549's two reported instances directly settles which of them
// the gap still affects, and the answer is different for each:
//
//   - BulkRejectAccessRequests / BulkApproveAccessRequests: diff vs the
//     pre-fault state is [AuditEvent] — an outcome-log table. Already accepted
//     by the error branch's onlyOutcomeLogTables, logged ACCEPTABLE-BY-DESIGN,
//     and the oracle never reaches report(). The four knownOpenTolerances that
//     cited #2549 for these were therefore DEAD — never consulted, still
//     carrying a 2026-10-17 expiry that would have produced re-filing churn for
//     a case nothing flags. They are deleted, and
//     TestOracleAErrorBranch_BulkAccessRequestAuditDiffIsAcceptedWithoutATolerance
//     pins what actually covers them so they cannot return as cargo-cult rows.
//   - VerifyMFAStepUp: diff is [MFASecret]. That is BUSINESS state, not an
//     outcome log, so no existing exemption reaches it and the tolerance was
//     genuinely load-bearing. But a tolerance is the wrong instrument: it means
//     "a filed, not-yet-fixed bug, tolerated until someone fixes it", and this
//     is not a bug — VerifyMFAStepUp's own doc comment and
//     TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed both establish
//     "consume the TOTP step first, fail closed if the grant write fails" as the
//     INTENDED design (a replayed code must not become reusable because the
//     grant write failed). Tolerating a by-design behaviour under an expiring
//     bug tolerance guarantees it is re-filed forever.
//
// So the exemption this file adds is narrow by construction and aimed at
// exactly that shape: a reported ERROR that intentionally leaves a
// business-state table mutated, where the mutation IS the security behaviour.
//
// Why not just widen onlyOutcomeLogTables, or add a tables entry to some
// existing map
// ------------------------------------------------------------------------
//   - onlyOutcomeLogTables is deliberately table-based and op-independent. It
//     is safe that way only because an outcome log is, by definition, not
//     application state. MFASecret is application state; accepting it
//     unconditionally for every op would be exactly the blanket skip #2549
//     says not to build.
//   - opScopedBestEffortTables (opScopedAcceptableByDesign) is about a
//     best-effort side effect the code is willing to LOSE. This is the
//     opposite: a mutation the code deliberately KEEPS while reporting failure.
//     Filing it there would make the next reader believe the TOTP consume is
//     discardable, which is the one thing it must not be.
//
// What this mechanism does NOT do, stated explicitly
// --------------------------------------------------
//   - It does not verify its own rows' claims. Each row cites the production
//     doc comment and the unit test that establish the design; those citations
//     are prose and this file does not re-derive them. What it does enforce is
//     that each row HAS them (TestOracleAByDesign_RowsAreFullyAttributed) and
//     that each row still matches something real
//     (TestOracleAByDesign_RowsAreLoadBearing).
//   - It only covers the error-reporting branch's business-state case. The
//     success branch and oracle (d) are untouched.
//   - A row's tables list is an exact allowlist, subset-checked. A diff with
//     even one table outside it still fails loudly.
package faultops

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// oracleAByDesignError is one reviewed exemption for oracle (a)'s
// error-reporting branch: an (op, method, kind) whose reported failure
// intentionally leaves exactly `tables` mutated.
//
// Every field is required. A row missing its design citation or its proving
// test is rejected by TestOracleAByDesign_RowsAreFullyAttributed — the point of
// the row is that someone traced the behaviour to an intentional design and
// left the evidence, not that someone silenced a failing oracle.
type oracleAByDesignError struct {
	// op is the opCatalog key. Required.
	op string
	// method is the faulted storage method. Required and never blank: a
	// wildcard would make this a per-op blanket skip, which is what #2549
	// says not to build.
	method string
	// kind is the fault kind this applies to. KindEffectThenError is
	// deliberately NOT accepted here — that shape is oracle (d)'s, which has
	// its own, differently-reasoned exclusions.
	kind faultstorage.FaultKind
	// nth, when > 0, pins the call ordinal. 0 means any.
	nth int
	// tables is the EXACT set of tables the reported failure may leave
	// diverged from the pre-fault state. Subset-checked: a diff containing
	// anything else is a different, unexplained divergence and still fails.
	// Required and non-empty.
	tables []string
	// designComment names where in PRODUCTION code the intent is stated, so a
	// reader can check the claim at its source rather than trusting this row.
	// Required.
	designComment string
	// provingTest is the test that already demonstrates this behaviour is the
	// intended one. Required — without it this row is an assertion, and an
	// assertion is what a tolerance already was.
	provingTest string
	// why is the one-paragraph reason the mutation is deliberate AND safe to
	// leave in place on the error path. Required.
	why string
}

// oracleAByDesignErrors is the reviewed inventory. Adding a row is a claim
// that the divergence is intended security behaviour, with the citations to
// back it. If you are not sure, it belongs in knownOpenTolerances (a filed,
// expiring, tracked-open bug) instead — that is the honest instrument for
// "this looks wrong and nobody has fixed it yet".
var oracleAByDesignErrors = []oracleAByDesignError{
	{
		op:     "REST POST /api/v1/auth/mfa/stepup",
		method: "CreateMFAStepUpGrant",
		kind:   faultstorage.KindError,
		nth:    1,
		tables: []string{"MFASecret"},
		designComment: "internal/core/mfa_stepup.go: VerifyMFAStepUp consumes the TOTP step " +
			"(advancing MFASecret's replay window) BEFORE minting the step-up grant, and fails " +
			"closed if the grant write fails",
		provingTest: "internal/core/TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed",
		why: "The consume is not a side effect of the grant — it is the single-use enforcement. " +
			"Rolling it back when CreateMFAStepUpGrant fails would hand the caller a code that is " +
			"still valid, so a caller who can induce a storage failure could replay one TOTP code " +
			"indefinitely. The reported ERROR is correct (no grant was issued, so no elevated " +
			"action is authorized), and MFASecret's advance is the security property, not a " +
			"partial commit. Previously carried as a knownOpenTolerance citing #2549, which " +
			"mis-labelled intended behaviour as a filed-but-unfixed bug and so guaranteed " +
			"perpetual re-filing at each expiry.",
	},
}

// oracleAErrorByDesign reports whether an error-reporting-branch oracle (a)
// divergence is covered by a reviewed row. Mirrors acceptableByDesign /
// opScopedAcceptableByDesign's subset semantics deliberately, so all three
// exemption mechanisms narrow a diff the same way.
func oracleAErrorByDesign(op, method string, kind faultstorage.FaultKind, nth int, diff []string) *oracleAByDesignError {
	if len(diff) == 0 {
		return nil
	}
	for i := range oracleAByDesignErrors {
		e := &oracleAByDesignErrors[i]
		if e.op != op || e.method != method || e.kind != kind {
			continue
		}
		if e.nth > 0 && e.nth != nth {
			continue
		}
		if diffSubsetOf(diff, e.tables) {
			return e
		}
	}
	return nil
}

// ── Guards on the mechanism itself ──────────────────────────────────────────

// TestOracleAByDesign_RowsAreFullyAttributed enforces the struct's own doc
// comment: every field is required, and the two citation fields in particular.
// A row that merely asserts "by design" is a tolerance with better branding.
func TestOracleAByDesign_RowsAreFullyAttributed(t *testing.T) {
	t.Parallel()
	for _, e := range oracleAByDesignErrors {
		label := fmt.Sprintf("%s/%s/%s", e.op, e.method, e.kind)
		if e.op == "" || e.method == "" {
			t.Errorf("oracleAByDesignError %q: op and method are both required — a blank method would make "+
				"this a per-op blanket skip, which #2549 explicitly rules out", label)
		}
		if e.kind == faultstorage.KindEffectThenError {
			t.Errorf("oracleAByDesignError %q: KindEffectThenError belongs to oracle (d), which has its own "+
				"exclusions and its own reasoning — this mechanism covers the error-reporting branch only", label)
		}
		if len(e.tables) == 0 {
			t.Errorf("oracleAByDesignError %q: tables is empty, which would accept ANY divergence for this "+
				"(op, method, kind) — the exact opposite of a narrow exemption", label)
		}
		for _, tb := range e.tables {
			if isOutcomeLogTable(tb) {
				t.Errorf("oracleAByDesignError %q: table %q is an outcome log, already accepted "+
					"unconditionally by onlyOutcomeLogTables — a row for it would be dead on arrival "+
					"(exactly how #2549's four bulk-op tolerances went stale)", label, tb)
			}
		}
		if e.designComment == "" {
			t.Errorf("oracleAByDesignError %q: designComment is required — name where production code states "+
				"this intent so the claim is checkable at its source", label)
		}
		if e.provingTest == "" {
			t.Errorf("oracleAByDesignError %q: provingTest is required — the test that already demonstrates "+
				"this is intended behaviour. Without one, this row is an assertion, which is what a "+
				"knownOpenTolerance already was", label)
		}
		if len(e.why) < 80 {
			t.Errorf("oracleAByDesignError %q: why is %d chars — too short to carry a reason. State why the "+
				"mutation is deliberate AND why leaving it in place on the error path is safe",
				label, len(e.why))
		}
	}
}

// TestOracleAByDesign_RowsAreLoadBearing drives each row's own (op, method,
// nth) case and asserts the oracle really does produce the divergence the row
// exempts.
//
// This is the check whose absence let four of #2549's tolerances go dead: the
// error branch grew onlyOutcomeLogTables, those tolerances stopped being
// consulted, and nothing noticed — they sat as expiring carve-outs for a case
// nothing flagged. A row that no longer matches anything must be REMOVED, not
// left as decoration, because a reader seeing it reasonably concludes the
// oracle still flags that case.
func TestOracleAByDesign_RowsAreLoadBearing(t *testing.T) {
	for _, e := range oracleAByDesignErrors {
		e := e
		label := fmt.Sprintf("%s/%s/%s", e.op, e.method, e.kind)
		t.Run(label, func(t *testing.T) {
			in, ok := driveFaultCase(t, e.op, e.method, e.nth, e.kind)
			if !ok {
				t.Fatalf("oracleAByDesignError %q: its own (op, method) could not be driven — the op is "+
					"not in opCatalog, or the method is not a storage.Storage method. A row that cannot "+
					"be exercised cannot be trusted", label)
			}
			if in.result.Success {
				t.Fatalf("oracleAByDesignError %q: this op reported SUCCESS under its own fault, so it never "+
					"reaches the error-reporting branch this mechanism covers. Either the behaviour changed "+
					"(remove the row) or the row names the wrong case", label)
			}
			diff := diffTables(in.before, in.after)
			if len(diff) == 0 {
				t.Fatalf("oracleAByDesignError %q: no state diverged at all, so oracle (a) would not flag "+
					"this case and the row is dead. Remove it", label)
			}
			if onlyOutcomeLogTables(diff) {
				t.Fatalf("oracleAByDesignError %q: the diff %v is outcome-log-only, already accepted by "+
					"onlyOutcomeLogTables before this mechanism is consulted — the row is dead. Remove it",
					label, diff)
			}
			if got := oracleAErrorByDesign(e.op, e.method, e.kind, e.nth, diff); got == nil {
				t.Fatalf("oracleAByDesignError %q: the real diff is %v, which this row's tables %v do not "+
					"cover — either the behaviour changed or the row's table list is wrong. NOT widened "+
					"automatically: an unexplained table is a different finding", label, diff, e.tables)
			}
			t.Logf("load-bearing: %s diverges in %v, covered by the reviewed row (proving test: %s)",
				label, diff, e.provingTest)
		})
	}
}

// TestKnownOpenTolerances_AreLoadBearing is the same staleness check applied to
// knownOpenTolerances, which is where the decay #2549 exposed actually lived.
//
// It does NOT re-derive checkOracles' accept-before-report ordering. It watches
// the real decision through observeKnownOpenMatch, which matchingKnownOpen
// calls on every tolerance it actually returns. A reconstruction of that
// ordering would be a second implementation of it, and a drifted copy would
// report a LIVE tolerance as dead and invite someone to delete a real
// carve-out — the one failure mode a staleness check must not have.
//
// Scope, stated rather than implied: it drives only the entries whose (op,
// method, nth, kind) are fully specified, because a blank-method wildcard entry
// gives the driver no method to fault. Those are listed by name in
// toleranceStalenessUndrivable below so the gap is visible instead of looking
// like full coverage. Narrowing it means giving the wildcard entries a
// representative method to drive — a schema change the coordinator should
// weigh, not something to invent here.
//
// Also not covered: an entry whose fault never fires for the (method, nth) it
// names is reported as undrivable, not dead, because "the fault did not fire"
// and "the oracle no longer flags it" are different facts and only the second
// justifies deleting a row.
func TestKnownOpenTolerances_AreLoadBearing(t *testing.T) {
	var dead, undrivable []string
	for _, k := range knownOpenTolerances {
		label := fmt.Sprintf("%s/%s/%s#%d", k.op, k.method, k.kind, k.nth)
		if k.method == "" || k.nth == 0 {
			if !toleranceStalenessUndrivable[label] {
				t.Errorf("knownOpenTolerance %q is not fully specified (blank method and/or nth==0) so this "+
					"staleness check cannot drive it, and it is not listed in "+
					"toleranceStalenessUndrivable. Add it there with a note, so the coverage gap is "+
					"visible rather than silent", label)
			}
			continue
		}
		consulted := false
		target := label
		prev := observeKnownOpenMatch
		observeKnownOpenMatch = func(got *knownOpenTolerance) {
			if fmt.Sprintf("%s/%s/%s#%d", got.op, got.method, got.kind, got.nth) == target {
				consulted = true
			}
		}
		_, ok := driveFaultCase(t, k.op, k.method, k.nth, k.kind)
		observeKnownOpenMatch = prev

		switch {
		case !ok:
			undrivable = append(undrivable, label)
		case !consulted:
			if _, known := toleranceDeadPendingTriage[label]; !known {
				dead = append(dead, label)
			}
		}
	}
	sort.Strings(dead)
	sort.Strings(undrivable)

	// Ratchet the other direction too: a baselined entry that came back to life
	// (or was deleted) must not sit in the baseline pretending to be debt.
	var revived []string
	for label := range toleranceDeadPendingTriage {
		stillListed := false
		for _, k := range knownOpenTolerances {
			if fmt.Sprintf("%s/%s/%s#%d", k.op, k.method, k.kind, k.nth) == label {
				stillListed = true
				break
			}
		}
		if !stillListed {
			revived = append(revived, label)
		}
	}
	sort.Strings(revived)
	if len(revived) > 0 {
		t.Errorf("found %d toleranceDeadPendingTriage entr(y/ies) whose knownOpenTolerance is gone: %v\n"+
			"The cleanup happened — remove the baseline row too, or this list outlives the debt it tracks.",
			len(revived), revived)
	}

	if len(undrivable) > 0 {
		t.Errorf("found %d knownOpenTolerance entr(y/ies) whose own (op, method, nth) could not be exercised "+
			"— the op key is stale, the storage method was renamed, or the fault never fires at that call "+
			"ordinal: %v\n"+
			"Re-triage each: a tolerance for a case the harness can no longer reach tolerates nothing, but "+
			"\"could not reach\" is NOT the same as \"no longer flagged\", so do not delete on this signal "+
			"alone.", len(undrivable), undrivable)
	}
	if len(dead) > 0 {
		t.Errorf("found %d knownOpenTolerance entr(y/ies) that no longer tolerate anything — their fault "+
			"fired, but the oracle did not report a violation for them, so matchingKnownOpen never "+
			"returned them: %v\n\n"+
			"Remove them. A dead tolerance is worse than no tolerance: it carries an expiry that produces "+
			"re-filing churn for a case nothing flags, and it tells a reader the oracle still reports that "+
			"case when it does not. This is exactly how four of #2549's own entries decayed unnoticed once "+
			"the error-reporting branch gained onlyOutcomeLogTables.\n\n"+
			"Before deleting, establish WHY each one went quiet — the fix landed, or an earlier "+
			"accept-by-design now shadows it. If it is the latter and the behaviour really is by design, "+
			"move it to oracleAByDesignErrors (this file) with its design citation and proving test rather "+
			"than just dropping it.", len(dead), dead)
	}
}

// toleranceDeadPendingTriage is the ratchet baseline: entries this check found
// already dead when it was introduced (#2549), each mapped to the issue that
// owns it. The check fails on a NEW dead entry, not on these — the
// inventory_ratchet_test.go idiom, so existing debt is visible with an owner
// instead of either blocking the build or being invisible.
//
// What I verified for each row below: its fault fires, the oracle reports no
// violation for it, and matchingKnownOpen therefore never returns it. What I
// did NOT verify: WHY each went quiet. That matters, because the right action
// differs — a tolerance dead because its fix LANDED should be removed by the
// fixing PR (CLAUDE.md: "The PR that fixes #NNNN removes its tolerance in the
// same PR"), while one dead because an earlier accept-by-design now shadows it
// may need to move to oracleAByDesignErrors with a design citation instead.
// Deciding that per entry belongs to the owner of each issue, not to #2549's
// mechanism change, and this file is a conflict hotspot every fuzzer PR touches
// (COMMON-RULES' shared-file rule) — so these are baselined and reported, not
// deleted here.
//
// The four #2549 bulk-op entries are NOT in this list: they were deleted in
// this same change, because #2549 owns them.
var toleranceDeadPendingTriage = map[string]string{
	"REST PUT /api/v1/projects/{id}/access-requests/{requestId}/CreateAccessRequestApproval/error#1": "#2407",
	"REST POST /auth/mfa/verify/GetMFASecret/error#1":                                                "#2548",
	"REST PATCH /api/v1/secrets/{id}/classification/CreateSecretAccessLog/panic#1":                   "#2554",
	"REST POST /api/v1/invitations/CountSetupTokensSince/error#1":                                    "#2599",
	// This one is the check's own positive control: #2570 fixed exactly the
	// behaviour its tolerance predicted (DecideAccessReviewItem's attest path
	// now runs its reads before the claim, so a ListProjectRoleAssignments
	// error leaves the item pending — proven by
	// internal/core/TestDecideAccessReviewItem_AttestGrantLookupErrorLeavesItemPending).
	// A tolerance for a fixed bug MUST read as dead, and this check says it
	// does. That is the evidence the check detects real staleness rather than
	// mis-reporting live entries.
	"REST POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide/ListProjectRoleAssignments/error#1": "#2606",
}

// toleranceStalenessUndrivable names the knownOpenTolerances entries
// TestKnownOpenTolerances_AreLoadBearing cannot drive, with why. Keeping the
// list explicit is the point: an unlisted undrivable entry fails the test, so
// the uncovered set cannot grow silently.
var toleranceStalenessUndrivable = map[string]bool{
	// method is deliberately blank (wildcard): the finding's root cause is
	// reserveLoginAttempt's unconditional write before the faulted call runs,
	// so ANY fault on this op shows the same LoginAttempt-only diff. There is
	// no single method to drive. Both fault kinds have their own entry (#2548).
	"REST POST /auth/mfa/verify//error#1": true,
	"REST POST /auth/mfa/verify//panic#1": true,
	// Same wildcard shape: a webauthn-login-finish failure's diff comes from a
	// write that lands before whichever call is faulted. Both fault kinds have
	// their own entry in knownOpenTolerances (#2565), and both are wildcards.
	"REST POST /auth/webauthn/login/finish//error#1": true,
	"REST POST /auth/webauthn/login/finish//panic#1": true,
}

// isOutcomeLogTable reports whether t is one of outcomeLogTables.
func isOutcomeLogTable(t string) bool {
	for _, o := range outcomeLogTables {
		if t == o {
			return true
		}
	}
	return false
}

// driveFaultCase runs ONE (op, method, nth, kind) case through the real harness
// and returns the oracleInput checkOracles would have seen. Shared by this
// file's staleness checks and the bulk-access-request pin below, so all of them
// observe exactly what the oracle observes rather than a reconstruction.
func driveFaultCase(t *testing.T, op, method string, nth int, kind faultstorage.FaultKind) (oracleInput, bool) {
	t.Helper()
	opIdx := -1
	for i, entry := range opCatalog {
		if entry.Key == op {
			opIdx = i
			break
		}
	}
	methodIdx := -1
	for i, m := range storageInterfaceMethodNames() {
		if m == method {
			methodIdx = i
			break
		}
	}
	if opIdx < 0 || methodIdx < 0 {
		return oracleInput{}, false
	}
	if nth < 1 {
		nth = 1
	}
	data := []byte{byte(opIdx), byte(methodIdx >> 8), byte(methodIdx), byte(nth - 1), fuzzKindSelector(kind)}

	var seen oracleInput
	got := false
	// The harness reports an unexempted violation via t.Errorf, which would
	// fail THIS test for a case it is only inspecting. Run it against a
	// throwaway *testing.T-shaped sink so only the observation escapes.
	runOneFuzzIterationWithWorlds(t, data, nil, nil, func(in oracleInput) {
		seen = in
		got = true
	})
	return seen, got
}

// fuzzKindSelector maps a FaultKind back to the selector byte decodeFuzzOp
// reads, so a case can be expressed in terms of the kind rather than a magic
// number. Kept adjacent to decodeFuzzOp's own mapping; a mismatch is caught by
// TestFuzzKindSelector_RoundTripsThroughDecode.
func fuzzKindSelector(kind faultstorage.FaultKind) byte {
	switch kind {
	case faultstorage.KindPanic:
		return 1
	case faultstorage.KindEffectThenError:
		return 2
	default:
		return 0
	}
}

// TestFuzzKindSelector_RoundTripsThroughDecode pins fuzzKindSelector against
// decodeFuzzOp's real mapping, so the staleness checks above cannot silently
// drive the wrong fault kind (and then report a row "dead" because it drove
// something else entirely).
func TestFuzzKindSelector_RoundTripsThroughDecode(t *testing.T) {
	t.Parallel()
	if len(opCatalog) == 0 {
		t.Skip("empty catalog")
	}
	methods := storageInterfaceMethodNames()
	if len(methods) == 0 {
		t.Skip("empty method list")
	}
	for _, kind := range []faultstorage.FaultKind{
		faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError,
	} {
		data := []byte{0, 0, 0, 0, fuzzKindSelector(kind)}
		decoded, ok := decodeFuzzOp(data)
		if !ok {
			t.Fatalf("decodeFuzzOp rejected a well-formed input for kind %s", kind)
		}
		if decoded.kind != kind {
			t.Errorf("fuzzKindSelector(%s) produced byte %d, which decodeFuzzOp reads back as %s — the "+
				"staleness checks would drive the wrong fault kind", kind, fuzzKindSelector(kind), decoded.kind)
		}
	}
}

// TestOracleAErrorBranch_BulkAccessRequestAuditDiffIsAcceptedWithoutATolerance
// pins what actually covers #2549's bulk-op instances now that their four
// tolerances are deleted: the error-reporting branch's own onlyOutcomeLogTables.
//
// Without this, a future reader hitting the same ACCEPTABLE-BY-DESIGN log line
// has no way to tell whether it is covered deliberately or by accident, and the
// natural response is to re-add a tolerance "just in case" — which is how the
// four dead ones accumulated in the first place.
func TestOracleAErrorBranch_BulkAccessRequestAuditDiffIsAcceptedWithoutATolerance(t *testing.T) {
	for _, c := range []struct{ op, method string }{
		{"REST POST /api/v1/access-requests/bulk-reject", "GetAccessRequest"},
		{"REST POST /api/v1/access-requests/bulk-approve", "GetAccessRequest"},
		{"REST POST /api/v1/access-requests/bulk-approve", "RoleSetBypassesPermissionChecks"},
		{"REST POST /api/v1/access-requests/bulk-approve", "GetRolePermissions"},
	} {
		c := c
		t.Run(strings.ReplaceAll(c.op+"/"+c.method, "/", "_"), func(t *testing.T) {
			nth := 1
			if c.method == "RoleSetBypassesPermissionChecks" {
				nth = 4 // the ordinal the deleted tolerance recorded
			}
			in, ok := driveFaultCase(t, c.op, c.method, nth, faultstorage.KindError)
			if !ok {
				t.Skipf("op %q / method %q not present in this catalog", c.op, c.method)
			}
			diff := diffTables(in.before, in.after)
			if len(diff) == 0 {
				t.Skip("no divergence to classify in this run")
			}
			if !onlyOutcomeLogTables(diff) {
				t.Fatalf("this case now diverges in %v, which is NOT outcome-log-only — the thing that "+
					"covered it after #2549 deleted its tolerance no longer applies. Re-triage before "+
					"re-adding any exemption: a business-state table here would be a real finding, not "+
					"the audit-content divergence the deleted tolerance described", diff)
			}
			t.Logf("covered by the error branch's onlyOutcomeLogTables (diff %v), no tolerance needed", diff)
		})
	}
}
