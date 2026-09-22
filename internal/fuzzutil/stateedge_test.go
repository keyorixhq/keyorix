package fuzzutil

import (
	"reflect"
	"testing"
)

// TestStateEdgeSwitch_EveryKeyDispatchesItsOwnDistinctCase proves the property
// stateedge_gen.go's doc comment claims -- each of the K cases calls a
// genuinely distinct function -- by pointer identity, not by re-reading the
// generated switch. A generator bug that collapsed two cases onto the same
// callee (or skipped one) would be invisible to a test that only calls
// StateEdge(key) and checks "no panic", since every case body is a no-op.
func TestStateEdgeSwitch_EveryKeyDispatchesItsOwnDistinctCase(t *testing.T) {
	seen := make(map[uintptr]int, stateEdgeK)
	for i, fn := range stateEdgeCaseFuncs {
		pc := reflect.ValueOf(fn).Pointer()
		if prev, ok := seen[pc]; ok {
			t.Fatalf("case %d shares its function with case %d (pc=%#x) -- not a distinct coverage edge", i, prev, pc)
		}
		seen[pc] = i
	}
	if len(seen) != stateEdgeK {
		t.Fatalf("got %d distinct case functions, want %d", len(seen), stateEdgeK)
	}
}

// TestStateEdge_DispatchesEveryInRangeKeyWithoutPanic exercises the full key
// space stateEdgeSwitch claims to cover -- every key in [0, StateEdgeK) must
// reach a case, not fall through the switch silently.
func TestStateEdge_DispatchesEveryInRangeKeyWithoutPanic(t *testing.T) {
	for key := uint32(0); key < StateEdgeK; key++ {
		StateEdge(key)
	}
}

func TestStateEdge_PanicsOnOutOfRangeKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("StateEdge(StateEdgeK) did not panic")
		}
	}()
	StateEdge(StateEdgeK)
}

func TestStateEdgeGate_FiresOncePerKeyPerGate(t *testing.T) {
	g := NewStateEdgeGate()
	g.FireOnce(5)
	g.FireOnce(5) // second call must be a no-op, not re-fire
	if !g.seen[5] {
		t.Fatal("key 5 not marked seen after FireOnce")
	}
	if g.seen[6] {
		t.Fatal("key 6 marked seen without ever being fired")
	}

	g2 := NewStateEdgeGate()
	if g2.seen[5] {
		t.Fatal("a fresh gate must not inherit state from a prior gate")
	}
}

func TestStateEdgeGate_PanicsOnOutOfRangeKey(t *testing.T) {
	g := NewStateEdgeGate()
	defer func() {
		if recover() == nil {
			t.Fatal("FireOnce(StateEdgeK) did not panic")
		}
	}()
	g.FireOnce(StateEdgeK)
}

func TestPackTuple_RoundTripsAndStaysWithinTupleSpace(t *testing.T) {
	sizes := []int{5, 3, 2, 3} // mirrors the core harness's current-tuple axis sizes
	space := TupleSpace(sizes)
	if space != 90 {
		t.Fatalf("TupleSpace(%v) = %d, want 90", sizes, space)
	}
	keysSeen := make(map[int]bool, space)
	for a := 0; a < sizes[0]; a++ {
		for b := 0; b < sizes[1]; b++ {
			for c := 0; c < sizes[2]; c++ {
				for d := 0; d < sizes[3]; d++ {
					key := PackTuple([]int{a, b, c, d}, sizes)
					if key < 0 || key >= space {
						t.Fatalf("PackTuple(%d,%d,%d,%d) = %d, out of [0,%d)", a, b, c, d, key, space)
					}
					if keysSeen[key] {
						t.Fatalf("PackTuple(%d,%d,%d,%d) = %d collides with an earlier tuple", a, b, c, d, key)
					}
					keysSeen[key] = true
				}
			}
		}
	}
	if len(keysSeen) != space {
		t.Fatalf("got %d distinct keys, want %d (every tuple must map to a distinct key)", len(keysSeen), space)
	}
}

func TestPackTuple_PanicsOnOutOfRangeDigit(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("PackTuple did not panic on an out-of-range digit")
		}
	}()
	PackTuple([]int{5}, []int{5}) // digit 5 is out of range for size 5 ([0,5))
}

func TestPackTuple_PanicsOnLengthMismatch(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("PackTuple did not panic on a digits/sizes length mismatch")
		}
	}()
	PackTuple([]int{0, 0}, []int{5})
}
