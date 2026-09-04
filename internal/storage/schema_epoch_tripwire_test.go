// schema_epoch_tripwire_test.go — #1674 / ADR-100.
//
// currentSchemaEpoch's monotonic-refusal mechanism (ADR-097) is a known,
// deliberately-not-yet-fixed gap for multi-replica rolling upgrades: it cannot
// distinguish "a sibling replica already migrated, this pod is mid-rollout" from
// "an operator genuinely downgraded" (see docs/adr-100-schema-epoch-compatibility-
// floor.md for the full reasoning and the rejected alternatives). That gap is
// latent only because currentSchemaEpoch has never been bumped since ADR-097
// shipped -- the moment it is, the refusal becomes a real, live event for the
// first time, and retrofitting ADR-100's compatibility-floor design after that
// point means migrating the migration guard itself while replicas may already be
// running under the old semantics.
//
// This test is the enforcement mechanism ADR-100 itself requires: it fails the
// instant anyone bumps currentSchemaEpoch above 1, with a message pointing
// straight at the design decision that must land first. It is not a statement
// that raising the epoch is wrong -- it's a checkpoint ensuring whoever does it
// meets ADR-100 at the moment it matters, not by already having to know to go
// looking for it.
package storage

import "testing"

func TestCurrentSchemaEpoch_StillOne_SeeADR100(t *testing.T) {
	if currentSchemaEpoch != 1 {
		t.Fatalf(
			"currentSchemaEpoch is now %d (was 1) -- STOP: docs/adr-100-schema-epoch-compatibility-floor.md "+
				"records a design decision that must land BEFORE this bump, not after. The current "+
				"checkSchemaEpoch (ADR-097) hard-refuses ANY older binary against ANY newer epoch, "+
				"including the common safe case (an old replica mid-rollout, not actually downgraded) -- "+
				"ADR-100 replaces that with a declared per-migration compatibility floor so the refusal "+
				"only fires when a migration author actually said this schema isn't safe for older "+
				"binaries. Implement ADR-100's minCompatibleEpoch mechanism first, THEN update this "+
				"test's expected value alongside your epoch bump -- do not just raise the constant here.",
			currentSchemaEpoch)
	}
}
