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
// ADR-084's entry was removed the same day it was added (2026-09-07,
// corrected): its decision had already been implemented 5 days earlier
// (PR #1671, 2026-09-02), a fact nobody checked before writing "deferred,
// no target date" into the registry. This is the actual gap a duration-based
// tripwire has: it checks whether TIME has passed, never whether the
// underlying claim is still true, so it would not have caught this
// staleness either way, only a check against live implementation state
// would have. Kept as a documented lesson, not silently dropped from this
// comment: before adding an entry here, confirm the decision is still open
// against current code, not just against the ADR's own text.
//
// Each registry entry names: the ADR, a one-line statement of what remains
// undecided, the date the decision was opened (from `git log --follow
// --diff-filter=A`, not a guess), and a threshold duration chosen per-entry
// with its own stated reasoning — not a single global number, since these
// decisions differ in urgency and don't share a natural deadline the way
// ADR-101's schema-epoch bump does. Deliberately duration-based (age since
// opened), not event-triggered like ADR-101's own tripwire: these two ADRs
// have no single triggering code event to hook a test to (no "the moment X
// happens" like a schema-epoch bump) — the failure mode this guards against
// is calendar time passing with nobody revisiting the decision, so the
// tripwire has to be calendar-based too.
//
// When this fires: read the named ADR, make the (a)/(b)-shaped decision it
// declines to make (or confirm it's already been made elsewhere and update
// the ADR's Status), and either remove the entry below or push its
// openedDate/threshold out with a fresh, stated justification for the
// extension — do not just bump the threshold silently.
package core

import (
	"testing"
	"time"
)

// adrOpenDecision is one entry in the open-decision registry.
type adrOpenDecision struct {
	adr        string // e.g. "ADR-102"
	decision   string // one-line statement of what remains undecided
	openedDate string // RFC3339 date the decision was first recorded, from git history
	threshold  time.Duration
	reasoning  string // why this specific threshold, not a different one
}

// adrOpenDecisionRegistry is the extensible list task 2 of the 2026-09-07 ADR
// review asked for: "any ADR at Proposed (or Accepted-but-deferred) status
// carrying a security-relevant open decision gets a CI check that fails past
// a threshold age." Add an entry here, not a new bespoke test function, the
// next time this shape recurs.
var adrOpenDecisionRegistry = []adrOpenDecision{
	{
		adr:        "ADR-102",
		decision:   "system.write's blast radius: is it (a) intentionally break-glass/root-equivalent (fix = alerting) or (b) a routine operator role (fix = permission-scoping migration)? docs/adr-102-system-write-blast-radius.md explicitly declines to choose.",
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

func checkADROpenDecisionNotStale(t *testing.T, adr string) {
	t.Helper()
	for _, d := range adrOpenDecisionRegistry {
		if d.adr != adr {
			continue
		}
		opened, err := time.Parse("2006-01-02", d.openedDate)
		if err != nil {
			t.Fatalf("%s: openedDate %q does not parse as YYYY-MM-DD: %v", d.adr, d.openedDate, err)
		}
		age := time.Since(opened)
		if age > d.threshold {
			t.Fatalf(
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
		return
	}
	t.Fatalf("no registry entry found for %s in adrOpenDecisionRegistry -- this test's own "+
		"name promises to check that ADR; the registry entry was removed without removing "+
		"the test, or renamed without updating it", adr)
}
