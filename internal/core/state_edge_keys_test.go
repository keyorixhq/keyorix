package core

import (
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// TestCoreStateEdgeKeys_StayWithinStateEdgeK fails if FuzzCoreOperationSequence's
// tuple encoding can ever produce a key >= fuzzutil.StateEdgeK. Guarding this at
// the declaration site (coreCurrentSizes/coreTransitionSizes/coreCurrentBase/
// coreTransitionBase, core_sequence_fuzz_test.go) rather than trusting the
// arithmetic: a future axis added to either tuple, or a base offset changed
// without recomputing the other, must fail CI loudly instead of StateEdge
// panicking only when the fuzzer happens to reach the overflowing tuple.
func TestCoreStateEdgeKeys_StayWithinStateEdgeK(t *testing.T) {
	currentSpace := fuzzutil.TupleSpace(coreCurrentSizes)
	transitionSpace := fuzzutil.TupleSpace(coreTransitionSizes)

	if maxKey := coreCurrentBase + currentSpace - 1; uint32(maxKey) >= fuzzutil.StateEdgeK {
		t.Fatalf("core current-tuple max key %d >= StateEdgeK %d (base=%d space=%d)",
			maxKey, fuzzutil.StateEdgeK, coreCurrentBase, currentSpace)
	}
	if maxKey := coreTransitionBase + transitionSpace - 1; uint32(maxKey) >= fuzzutil.StateEdgeK {
		t.Fatalf("core transition-tuple max key %d >= StateEdgeK %d (base=%d space=%d)",
			maxKey, fuzzutil.StateEdgeK, coreTransitionBase, transitionSpace)
	}
	// The two ranges must not overlap -- a current-tuple key must never alias a
	// transition-tuple key, or the coverage-edge feedback and the human-readable
	// state-coverage report (FUZZ_STATE_REPORT) would conflate two different kinds
	// of tuple under one key.
	if coreTransitionBase < coreCurrentBase+currentSpace {
		t.Fatalf("core transition base %d overlaps current-tuple range [%d,%d)",
			coreTransitionBase, coreCurrentBase, coreCurrentBase+currentSpace)
	}

	// Exhaustively confirm every axis combination PackTuple can actually be
	// called with (mirroring step()'s real digit ranges) round-trips to a key
	// inside the declared space -- not just that the space's SIZE fits under K.
	seen := make(map[int]bool, currentSpace)
	for kind := 0; kind < coreCurrentSizes[0]; kind++ {
		for principal := 0; principal < coreCurrentSizes[1]; principal++ {
			for roleState := 0; roleState < coreCurrentSizes[2]; roleState++ {
				for pop := 0; pop < coreCurrentSizes[3]; pop++ {
					key := fuzzutil.PackTuple([]int{kind, principal, roleState, pop}, coreCurrentSizes)
					if key < 0 || key >= currentSpace {
						t.Fatalf("current tuple (%d,%d,%d,%d) key=%d out of [0,%d)", kind, principal, roleState, pop, key, currentSpace)
					}
					seen[key] = true
				}
			}
		}
	}
	if len(seen) != currentSpace {
		t.Fatalf("current tuple space covers %d distinct keys, want %d", len(seen), currentSpace)
	}
}

// TestEnumerateCoreStateLabels prints every label FuzzCoreOperationSequence's
// tuple encoding can ever produce (STATE-ENUM: prefixed, one per line) --
// scripts/fuzzing/state-coverage-diff.sh diffs this against a
// FUZZ_STATE_REPORT run to list UNREACHED security states. It reuses
// coreCurrentLabel/coreTransitionLabel, the exact functions the real harness
// calls while fuzzing, so the enumeration can't drift from what fuzzing
// actually reports.
func TestEnumerateCoreStateLabels(t *testing.T) {
	for kind := 0; kind < coreCurrentSizes[0]; kind++ {
		for principal := 0; principal < coreCurrentSizes[1]; principal++ {
			for roleState := 0; roleState < coreCurrentSizes[2]; roleState++ {
				for pop := 0; pop < coreCurrentSizes[3]; pop++ {
					fmt.Println("STATE-ENUM: " + coreCurrentLabel(kind, principal, roleState, pop))
					for prior := 0; prior < coreTransitionSizes[0]; prior++ {
						fmt.Println("STATE-ENUM: " + coreTransitionLabel(prior, kind, principal, roleState, pop))
					}
				}
			}
		}
	}
}
