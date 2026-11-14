package fuzzutil

import (
	"math/rand"
	"testing"
)

// TestSwarmAllOnesIsFullAlphabet pins the seed-compatibility contract: an
// all-ones mask enables every element, in order, for a range of alphabet sizes
// (including n > 64, where bits are shared). This is why prepending ^uint64(0)
// to an existing seed preserves its meaning.
func TestSwarmAllOnesIsFullAlphabet(t *testing.T) {
	for _, n := range []int{1, 2, 7, 8, 63, 64, 65, 150, 300} {
		s := NewSwarm(^uint64(0), n)
		if s.Len() != n {
			t.Fatalf("n=%d: all-ones enabled %d, want %d", n, s.Len(), n)
		}
		if !s.IsFull() {
			t.Fatalf("n=%d: all-ones not reported full", n)
		}
		for i := range n {
			if !s.Has(i) {
				t.Fatalf("n=%d: all-ones did not enable index %d", n, i)
			}
			if got := s.Pick(i); got != i {
				t.Fatalf("n=%d: all-ones Pick(%d)=%d, want %d", n, i, got, i)
			}
		}
	}
}

// TestSwarmNeverEmpty: whatever the mask, the enabled set is non-empty for a
// non-empty alphabet. mask==0 and masks that select no in-range bit fall back to
// the full alphabet rather than an empty one.
func TestSwarmNeverEmpty(t *testing.T) {
	for _, n := range []int{1, 3, 8, 64, 65, 200} {
		for _, mask := range []uint64{0, 1, 2, 0xAAAAAAAAAAAAAAAA, 0x5555555555555555, 1 << 63, ^uint64(0)} {
			s := NewSwarm(mask, n)
			if s.Len() < 1 {
				t.Fatalf("n=%d mask=%#x: empty enabled set", n, mask)
			}
			// Pick must always land on an enabled index.
			for raw := -3; raw < 300; raw++ {
				if !s.Has(s.Pick(raw)) {
					t.Fatalf("n=%d mask=%#x: Pick(%d)=%d not enabled", n, mask, raw, s.Pick(raw))
				}
			}
		}
	}
	// mask==0 specifically falls back to full, not empty.
	s := NewSwarm(0, 8)
	if !s.IsFull() || s.Len() != 8 {
		t.Fatalf("mask=0 should fall back to the full alphabet, got len=%d full=%v", s.Len(), s.IsFull())
	}
	// A mask whose only set bits are above the alphabet size (n<64) also falls back.
	s = NewSwarm(uint64(1)<<40, 8)
	if !s.IsFull() {
		t.Fatalf("out-of-range-only mask should fall back to full for n=8")
	}
}

// TestSwarmDecodeBits: for n<=64, element i is enabled exactly when bit i is set.
func TestSwarmDecodeBits(t *testing.T) {
	// 0b1011 -> indices 0,1,3 enabled; index 2 disabled.
	s := NewSwarm(0b1011, 4)
	want := map[int]bool{0: true, 1: true, 2: false, 3: true}
	for i, w := range want {
		if s.Has(i) != w {
			t.Fatalf("mask=0b1011 n=4: Has(%d)=%v, want %v", i, s.Has(i), w)
		}
	}
	if s.Len() != 3 {
		t.Fatalf("mask=0b1011 n=4: Len=%d, want 3", s.Len())
	}
	if s.IsFull() {
		t.Fatalf("mask=0b1011 n=4 should not be full")
	}
	// Pick cycles over exactly {0,1,3}.
	seen := map[int]int{}
	for raw := range 9 {
		seen[s.Pick(raw)]++
	}
	if seen[2] != 0 {
		t.Fatalf("Pick returned the disabled index 2")
	}
	if len(seen) != 3 {
		t.Fatalf("Pick covered %d indices, want 3", len(seen))
	}
}

// TestSwarmBitsShared documents the n>64 behaviour: index i tracks bit (i mod
// 64), so indices 64 apart share a bit. This is a documented property, asserted
// so a future change to the sharing scheme is caught.
func TestSwarmBitsShared(t *testing.T) {
	s := NewSwarm(0b1, 130) // only bit 0 set
	for _, i := range []int{0, 64, 128} {
		if !s.Has(i) {
			t.Fatalf("bit 0 set: index %d (==0 mod 64) should be enabled", i)
		}
	}
	if s.Has(1) || s.Has(65) {
		t.Fatalf("bit 0 only: index 1/65 should be disabled")
	}
	if s.Len() != 3 {
		t.Fatalf("bit0 over n=130: Len=%d, want 3 (indices 0,64,128)", s.Len())
	}
}

// TestSwarmDeterministic: same (mask,n) yields identical enabled sets and Pick
// results across independent constructions — fuzzing replay depends on this.
func TestSwarmDeterministic(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for range 2000 {
		mask := r.Uint64()
		n := 1 + r.Intn(200)
		a := NewSwarm(mask, n)
		b := NewSwarm(mask, n)
		if a.Len() != b.Len() {
			t.Fatalf("mask=%#x n=%d: non-deterministic Len %d vs %d", mask, n, a.Len(), b.Len())
		}
		ea, eb := a.Enabled(), b.Enabled()
		for i := range ea {
			if ea[i] != eb[i] {
				t.Fatalf("mask=%#x n=%d: enabled set differs at %d", mask, n, i)
			}
		}
		for raw := 0; raw < 50; raw++ {
			if a.Pick(raw) != b.Pick(raw) {
				t.Fatalf("mask=%#x n=%d: Pick(%d) non-deterministic", mask, n, raw)
			}
		}
	}
}

// TestSwarmEmptyAlphabet: n<=0 is a safe no-op, not a panic.
func TestSwarmEmptyAlphabet(t *testing.T) {
	for _, n := range []int{0, -1} {
		s := NewSwarm(^uint64(0), n)
		if s.Len() != 0 {
			t.Fatalf("n=%d: Len=%d, want 0", n, s.Len())
		}
		if s.Pick(5) != 0 {
			t.Fatalf("n=%d: Pick on empty alphabet should return 0", n)
		}
		if s.Has(0) {
			t.Fatalf("n=%d: Has(0) should be false on empty alphabet", n)
		}
	}
}

// TestSwarmSubsetDiversity is the property that motivates swarm testing: over
// many random masks, the generator reaches many DISTINCT alphabet subsets,
// including subsets that omit any given element — which an all-ones (uniform)
// generator never does. This is a helper-level sanity check of the mechanism;
// the per-fuzzer coverage/shape evidence lives with each fuzzer.
func TestSwarmSubsetDiversity(t *testing.T) {
	const n = 8
	r := rand.New(rand.NewSource(7))
	subsets := map[uint8]struct{}{}
	omitsEach := make([]int, n)
	for range 5000 {
		s := NewSwarm(r.Uint64(), n)
		var key uint8
		for i := range n {
			if s.Has(i) {
				key |= 1 << uint(i)
			} else {
				omitsEach[i]++
			}
		}
		subsets[key] = struct{}{}
	}
	if len(subsets) < 200 {
		t.Fatalf("swarm reached only %d distinct subsets of %d elements, expected most of 2^%d", len(subsets), n, n)
	}
	for i := range n {
		if omitsEach[i] == 0 {
			t.Fatalf("no sampled mask omitted element %d — swarm is not disabling features", i)
		}
	}
}
