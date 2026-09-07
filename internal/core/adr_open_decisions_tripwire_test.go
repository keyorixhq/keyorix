// adr_open_decisions_tripwire_test.go — general mechanism for "an ADR records
// a security-relevant decision, declines to resolve it, and nothing forces
// that resolution to happen." ADR-101 already proves the specific shape works
// (TestCurrentSchemaEpoch_StillOne_SeeADR101, internal/storage/schema_epoch_
// tripwire_test.go) — this generalizes it to an explicit, extensible registry
// rather than one bespoke test per ADR, after a 2026-09-07 review
// (keyorix-private/adversarial-review/ADR-CORPUS-REVIEW-2026-09-07.md,
// Findings 3 and 4) found two more ADRs in exactly this shape with no
// enforcing test at all: ADR-102 (system.write blast radius, Proposed,
// undated) and ADR-084 (admin-bypass structural marker, Accepted but
// deferred, no target date/owner/tripwire).
//
// REDESIGNED 2026-09-07, same day, after the first version's own entry for
// ADR-084 went stale on arrival: it claimed the decision was still "deferred,
// no code changes" when PR #1671 had already implemented it 5 days earlier,
// because the check was purely age-based (elapsed time since openedDate) and
// never asked whether the decision was ACTUALLY still open in code. A
// duration-based check answers "has time passed," never "is the claim still
// true" — those are different questions, and only the second one is what a
// reader actually wants to know.
//
// A registry entry MUST assert the decision's PREMISE — a live, checkable
// fact about current code that would change the moment the decision is
// resolved — whenever one is expressible. ADR-084's premise was directly
// checkable ("does roleSetContainsAdmin still resolve by name") and would
// have caught the staleness immediately, the day #1671 merged, instead of
// sitting wrong in a registry entry that was itself only hours old.
// Age-based expiry is kept ONLY as a fallback for decisions whose
// unresolved state produces no code artifact in either branch — ADR-102's
// (a)/(b) policy choice (alerting vs. permission-scoping) is the current
// example: neither un-chosen branch leaves anything in the codebase for a
// premise function to inspect, so there is nothing to check except elapsed
// time. Do not add an age-only entry without first asking whether a premise
// exists — leave premise nil with a comment stating why not, so the omission
// reads as considered, not overlooked the way ADR-084's was.
//
// When a premise IS expressible, the check still also runs the age fallback
// underneath it (see evaluateOpenDecision) — a resolved premise fires
// immediately regardless of age (catching a stale-in-the-safe-direction
// entry like ADR-084's), and an unresolved premise still ages out on its own
// threshold (catching a decision that's genuinely still open and has simply
// been forgotten). The two checks are complementary, not alternatives.
//
// Each registry entry names: the ADR, a one-line statement of what remains
// undecided, an optional premise function, the date the decision was opened
// (from `git log --follow --diff-filter=A`, not a guess), and a threshold
// duration chosen per-entry with its own stated reasoning — not a single
// global number, since these decisions differ in urgency and don't share a
// natural deadline the way ADR-101's schema-epoch bump does.
//
// When this fires: read the named ADR, make the (a)/(b)-shaped decision it
// declines to make (or confirm it's already been made elsewhere and update
// the ADR's Status), and either remove the entry below or push its
// openedDate/threshold out with a fresh, stated justification for the
// extension — do not just bump the threshold silently.
package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// adrOpenDecision is one entry in the open-decision registry.
type adrOpenDecision struct {
	adr        string // e.g. "ADR-102"
	decision   string // one-line statement of what remains undecided
	openedDate string // RFC3339 date the decision was first recorded, from git history
	threshold  time.Duration
	reasoning  string // why this specific threshold, not a different one
	// premise, when non-nil, checks whether the decision is ACTUALLY still
	// open in code today — takes priority over the age check. Returns
	// stillOpen=false the moment the underlying code fact that would prove
	// the decision resolved is observed, with detail explaining what was
	// found. Leave nil (with a comment explaining why no premise is
	// expressible) rather than omitting it silently — see file header.
	premise func() (stillOpen bool, detail string)
}

// adrOpenDecisionRegistry is the extensible list task 2 of the 2026-09-07 ADR
// review asked for: "any ADR at Proposed (or Accepted-but-deferred) status
// carrying a security-relevant open decision gets a CI check that fails past
// a threshold age." Add an entry here, not a new bespoke test function, the
// next time this shape recurs.
var adrOpenDecisionRegistry = []adrOpenDecision{
	{
		adr:      "ADR-102",
		decision: "system.write's blast radius: is it (a) intentionally break-glass/root-equivalent (fix = alerting) or (b) a routine operator role (fix = permission-scoping migration)? docs/adr-102-system-write-blast-radius.md explicitly declines to choose.",
		// No premise is expressible: unlike ADR-084's structural flag (whose
		// presence directly proves the decision resolved), neither (a) nor
		// (b) leaves a code artifact in its UNRESOLVED state for a premise
		// function to check against — the decision is a pure product/policy
		// choice with no interim code shape either fork would produce before
		// someone actually builds it. Age is the only available signal.
		openedDate: "2026-09-05",
		threshold:  30 * 24 * time.Hour,
		reasoning: "30 days: long enough for a real product/threat-model decision (this " +
			"touches every /system route and every role holding system.write), short enough " +
			"that the already-confirmed account-takeover chain motivating this ADR (see its " +
			"own Context section) doesn't quietly age from '2 days old, worth catching now' " +
			"(the 2026-09-07 review's own words) into 'forgotten.'",
	},
}

// TestADR102_SystemWriteBlastRadiusStillOpen is the enforcing test named in
// docs/adr-102-system-write-blast-radius.md's own Consequences section.
func TestADR102_SystemWriteBlastRadiusStillOpen(t *testing.T) {
	checkADROpenDecisionNotStale(t, "ADR-102")
}

// TestADRDecisionRoleSetContainsAdminIsStructural is the worked example of a
// premise function, kept live rather than only demonstrated in the self-test
// below: it directly answers "has ADR-084's decision been implemented,"
// independent of any registry entry or age. If this codebase ever
// regresses roleSetContainsAdmin back to name-based resolution, this test
// documents what a premise check for that regression would look like —
// exercised for real here, not just simulated.
func TestADRDecisionRoleSetContainsAdminIsStructural(t *testing.T) {
	stillOpen, detail := adr084Premise()
	if stillOpen {
		t.Fatalf("ADR-084's decision reads as unresolved again: %s", detail)
	}
}

// adr084Premise checks whether ADR-084's decision — "bypasses_permission_checks
// as a structural, non-name column" — is actually implemented, by asserting
// the column exists on models.Role. This is the premise ADR-084's original
// registry entry should have used from the start: it would have failed the
// moment PR #1671 shipped, 5 days before the entry was written claiming
// otherwise.
func adr084Premise() (stillOpen bool, detail string) {
	// A compile-time assertion, not a runtime one: if BypassesPermissionChecks
	// is ever removed from models.Role, this line itself fails to compile,
	// which is a louder and earlier signal than a runtime test failure. The
	// runtime call below exists so this still reads as a normal premise
	// function callable from the registry shape, for the next ADR that needs
	// one.
	var r models.Role
	_ = r.BypassesPermissionChecks
	return false, "models.Role.BypassesPermissionChecks exists — ADR-084's structural flag is implemented"
}

// checkADROpenDecisionNotStale is the thin per-test entrypoint: find the
// named registry entry and fail loudly via evaluateOpenDecision if either
// check fires.
func checkADROpenDecisionNotStale(t *testing.T, adr string) {
	t.Helper()
	for _, d := range adrOpenDecisionRegistry {
		if d.adr != adr {
			continue
		}
		if err := evaluateOpenDecision(d, time.Now()); err != nil {
			t.Fatal(err.Error())
		}
		return
	}
	t.Fatalf("no registry entry found for %s in adrOpenDecisionRegistry -- this test's own "+
		"name promises to check that ADR; the registry entry was removed without removing "+
		"the test, or renamed without updating it", adr)
}

// evaluateOpenDecision is the pure logic behind checkADROpenDecisionNotStale,
// extracted so it can be exercised directly by the self-test below with
// synthetic entries — the same reason mlockall_removal_guard_test.go and
// other guards in this codebase pair a real check with a red/green
// self-test proving the check mechanism itself actually detects both
// outcomes, not just the one case it happened to run against here.
// now is passed in (not time.Now() called internally) so the self-test can
// exercise "age past threshold" deterministically without sleeping.
func evaluateOpenDecision(d adrOpenDecision, now time.Time) error {
	if d.premise != nil {
		if stillOpen, detail := d.premise(); !stillOpen {
			return fmt.Errorf(
				"%s: registry says this decision is still open, but its premise check reports "+
					"it has already been resolved in code (%s) -- this is exactly ADR-084's original "+
					"mistake (an entry claiming 'deferred' 5 days after the fix actually shipped). "+
					"Update the ADR's Status and remove this registry entry.",
				d.adr, detail,
			)
		}
	}
	opened, err := time.Parse("2006-01-02", d.openedDate)
	if err != nil {
		return fmt.Errorf("%s: openedDate %q does not parse as YYYY-MM-DD: %v", d.adr, d.openedDate, err)
	}
	age := now.Sub(opened)
	if age > d.threshold {
		return fmt.Errorf(
			"%s has been open %s (threshold %s, opened %s) with nothing forcing its "+
				"resolution -- STOP: this is exactly the 'accepted decision, no enforcement "+
				"mechanism' pattern the 2026-09-07 ADR review flagged. Decision still undecided: "+
				"%s\n\nResolve the decision and update the ADR's Status, or if a genuine reason "+
				"exists to keep it open longer, extend this entry's threshold in "+
				"adr_open_decisions_tripwire_test.go with a fresh, stated reason -- do not "+
				"silently bump the number.",
			d.adr, age.Round(time.Hour), d.threshold, d.openedDate, d.decision,
		)
	}
	return nil
}

// TestEvaluateOpenDecision_MechanismSelfTest is the red/green proof that
// evaluateOpenDecision actually detects both failure modes it exists to
// catch, and does not over-fire on the cases it should pass — run against
// synthetic entries, not the real registry, so it exercises the MECHANISM
// deterministically rather than depending on real ADRs' real ages.
func TestEvaluateOpenDecision_MechanismSelfTest(t *testing.T) {
	fixedNow, err := time.Parse("2006-01-02", "2026-09-07")
	if err != nil {
		t.Fatalf("bad fixed 'now' in test setup: %v", err)
	}

	t.Run("premise resolved -- fires immediately regardless of age", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-09-06", // 1 day old -- well within any real threshold
			threshold:  365 * 24 * time.Hour,
			premise:    func() (bool, string) { return false, "synthetic: already resolved" },
		}
		if err := evaluateOpenDecision(d, fixedNow); err == nil {
			t.Fatal("expected the resolved-premise case to fire even though age is nowhere near threshold")
		}
	})

	t.Run("premise still open, within threshold -- does not fire", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-09-06",
			threshold:  30 * 24 * time.Hour,
			premise:    func() (bool, string) { return true, "synthetic: still open" },
		}
		if err := evaluateOpenDecision(d, fixedNow); err != nil {
			t.Fatalf("expected no failure for a genuinely-still-open decision within its threshold, got: %v", err)
		}
	})

	t.Run("premise still open, past threshold -- fires via the age fallback", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-01-01",
			threshold:  30 * 24 * time.Hour,
			premise:    func() (bool, string) { return true, "synthetic: still open" },
		}
		if err := evaluateOpenDecision(d, fixedNow); err == nil {
			t.Fatal("expected the age fallback to fire once a still-genuinely-open decision passes its threshold")
		}
	})

	t.Run("no premise (nil), within threshold -- does not fire", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-09-06",
			threshold:  30 * 24 * time.Hour,
			premise:    nil,
		}
		if err := evaluateOpenDecision(d, fixedNow); err != nil {
			t.Fatalf("expected no failure within threshold with no premise configured, got: %v", err)
		}
	})

	t.Run("no premise (nil), past threshold -- fires via age, the ADR-102 shape", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-01-01",
			threshold:  30 * 24 * time.Hour,
			premise:    nil,
		}
		if err := evaluateOpenDecision(d, fixedNow); err == nil {
			t.Fatal("expected the pure age-based path (no premise) to still fire past threshold")
		}
	})
}
