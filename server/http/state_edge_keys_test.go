package http

import (
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// TestHTTPStateEdgeKeys_StayWithinStateEdgeK fails if FuzzKeyorixHTTPAPISequence's
// tuple encoding can ever produce a key >= fuzzutil.StateEdgeK. See
// internal/core's TestCoreStateEdgeKeys_StayWithinStateEdgeK for the same
// guard on the core harness -- this is the HTTP harness's twin, at the
// declaration site (httpCurrentSizes/httpTransitionSizes/httpCurrentBase/
// httpTransitionBase, api_sequence_fuzz_test.go).
func TestHTTPStateEdgeKeys_StayWithinStateEdgeK(t *testing.T) {
	currentSpace := fuzzutil.TupleSpace(httpCurrentSizes)
	transitionSpace := fuzzutil.TupleSpace(httpTransitionSizes)

	if maxKey := httpCurrentBase + currentSpace - 1; uint32(maxKey) >= fuzzutil.StateEdgeK {
		t.Fatalf("http current-tuple max key %d >= StateEdgeK %d (base=%d space=%d)",
			maxKey, fuzzutil.StateEdgeK, httpCurrentBase, currentSpace)
	}
	if maxKey := httpTransitionBase + transitionSpace - 1; uint32(maxKey) >= fuzzutil.StateEdgeK {
		t.Fatalf("http transition-tuple max key %d >= StateEdgeK %d (base=%d space=%d)",
			maxKey, fuzzutil.StateEdgeK, httpTransitionBase, transitionSpace)
	}
	if httpTransitionBase < httpCurrentBase+currentSpace {
		t.Fatalf("http transition base %d overlaps current-tuple range [%d,%d)",
			httpTransitionBase, httpCurrentBase, httpCurrentBase+currentSpace)
	}

	// Exhaustively confirm every axis combination read()/fireReadStateEdge can
	// actually be called with (including revocationProbe's fixed
	// httpPrincipalRevuser/roleState=1/tenantMatch=0 calls, which are a subset
	// of this same space) round-trips to a key inside the declared range.
	seen := make(map[int]bool, currentSpace)
	for pk := 0; pk < httpCurrentSizes[0]; pk++ {
		for rs := 0; rs < httpCurrentSizes[1]; rs++ {
			for tm := 0; tm < httpCurrentSizes[2]; tm++ {
				for ts := 0; ts < httpCurrentSizes[3]; ts++ {
					key := fuzzutil.PackTuple([]int{pk, rs, tm, ts}, httpCurrentSizes)
					if key < 0 || key >= currentSpace {
						t.Fatalf("current tuple (%d,%d,%d,%d) key=%d out of [0,%d)", pk, rs, tm, ts, key, currentSpace)
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

// TestEnumerateHTTPStateLabels prints every label FuzzKeyorixHTTPAPISequence's
// tuple encoding can ever produce (STATE-ENUM: prefixed, one per line) --
// scripts/fuzzing/state-coverage-diff.sh diffs this against a
// FUZZ_STATE_REPORT run to list UNREACHED security states. It reuses
// httpCurrentLabel/httpTransitionLabel, the exact functions the real harness
// calls while fuzzing, so the enumeration can't drift from what fuzzing
// actually reports.
func TestEnumerateHTTPStateLabels(t *testing.T) {
	for pk := 0; pk < httpCurrentSizes[0]; pk++ {
		for rs := 0; rs < httpCurrentSizes[1]; rs++ {
			for tm := 0; tm < httpCurrentSizes[2]; tm++ {
				for ts := 0; ts < httpCurrentSizes[3]; ts++ {
					fmt.Println("STATE-ENUM: " + httpCurrentLabel(pk, rs, tm, ts))
					for prevOp := 0; prevOp < httpTransitionSizes[0]; prevOp++ {
						fmt.Println("STATE-ENUM: " + httpTransitionLabel(prevOp, pk, rs, tm, ts))
					}
				}
			}
		}
	}
}
