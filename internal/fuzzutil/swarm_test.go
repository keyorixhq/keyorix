package fuzzutil

import (
	"math/rand"
	"testing"
)

// TestSwarmAllOnesIsFullAlphabet pins the seed-compatibility contract: an
// all-ones mask enables every element, in order, for a range of alphabet sizes
// (including n > 64). This is why prepending ^uint64(0) to an existing seed
// preserves its meaning (Pick == raw % n).
func TestSwarmAllOnesIsFullAlphabet(t *testing.T) {
	for _, n := range []int{1, 2, 7, 8, 63, 64, 65, 150, 307} {
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
// non-empty alphabet, and every Pick lands on an enabled index.
func TestSwarmNeverEmpty(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	for _, n := range []int{1, 3, 8, 64, 65, 307, 1000} {
		for range 500 {
			mask := r.Uint64()
			s := NewSwarm(mask, n)
			if s.Len() < 1 {
				t.Fatalf("n=%d mask=%#x: empty enabled set", n, mask)
			}
			for raw := -3; raw < 50; raw++ {
				if !s.Has(s.Pick(raw)) {
					t.Fatalf("n=%d mask=%#x: Pick(%d)=%d not enabled", n, mask, raw, s.Pick(raw))
				}
			}
		}
	}
	// A high density exponent against a small alphabet selects nothing and must
	// fall back to full, not empty. Low nibble 0xF -> d=15 -> keep 1 in 32768.
	s := NewSwarm(0xFFFFFFFFFFFFFF0F, 8)
	if s.Len() == 0 {
		t.Fatalf("high-exponent small-alphabet mask produced an empty set")
	}
}

// TestSwarmDensityExponent pins the decoding: the low nibble is the density
// exponent and d==0 means density 1 (full). d>0 removes elements.
func TestSwarmDensityExponent(t *testing.T) {
	// Low nibble 0 -> density 1 -> every element enabled (but not the all-ones
	// special case; this exercises the general path).
	s := NewSwarm(0xABCD0, 8) // low nibble 0
	if s.Len() != 8 || !s.IsFull() {
		t.Fatalf("low-nibble-0 mask should be full, got len=%d full=%v", s.Len(), s.IsFull())
	}
	// A non-zero exponent must drop the density below 1 on a large alphabet.
	full, restricted := 0, 0
	r := rand.New(rand.NewSource(5))
	const n = 307
	for range 3000 {
		m := r.Uint64() | 0x0 // arbitrary
		if m&0xF == 0 || m == ^uint64(0) {
			continue // skip the density-1 cases for this measurement
		}
		s := NewSwarm(m, n)
		if s.Len() == n {
			full++
		} else {
			restricted++
		}
	}
	if restricted == 0 {
		t.Fatalf("no mask produced a restricted alphabet on n=%d", n)
	}
}

// TestSwarmProducesSmallSubsets is the property the density scheme exists for:
// over random masks on a LARGE alphabet, a meaningful fraction of executions
// enable only a SMALL subset (this is exactly what a naive per-bit mask could
// not do, which the SW1 report documents as the reason for this scheme).
func TestSwarmProducesSmallSubsets(t *testing.T) {
	const n = 307
	r := rand.New(rand.NewSource(13))
	small := 0 // subsets of <= n/8 elements
	const trials = 20000
	for range trials {
		s := NewSwarm(r.Uint64(), n)
		if s.Len() <= n/8 {
			small++
		}
	}
	if small < trials/20 {
		t.Fatalf("only %d/%d executions enabled a small (<=n/8) subset — density scheme not producing small subsets", small, trials)
	}
}

// TestSwarmEachElementOmittable: over random masks, every alphabet element is
// disabled in at least some executions — a uniform (all-ones) generator never
// omits any element, which is the gap swarm closes.
func TestSwarmEachElementOmittable(t *testing.T) {
	const n = 32
	r := rand.New(rand.NewSource(17))
	omitted := make([]int, n)
	for range 20000 {
		s := NewSwarm(r.Uint64(), n)
		for i := range n {
			if !s.Has(i) {
				omitted[i]++
			}
		}
	}
	for i := range n {
		if omitted[i] == 0 {
			t.Fatalf("element %d was never omitted — swarm is not disabling features", i)
		}
	}
}

// TestSwarmDeterministic: same (mask,n) yields identical enabled sets and Pick
// results across independent constructions — fuzzing replay depends on this.
func TestSwarmDeterministic(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for range 2000 {
		mask := r.Uint64()
		n := 1 + r.Intn(400)
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

// TestSwarmSubsetDiversity: over many random masks the generator reaches many
// DISTINCT subsets of a small alphabet, including subsets that omit any given
// element — which an all-ones (uniform) generator never does.
func TestSwarmSubsetDiversity(t *testing.T) {
	const n = 8
	r := rand.New(rand.NewSource(7))
	subsets := map[uint8]struct{}{}
	for range 20000 {
		s := NewSwarm(r.Uint64(), n)
		var key uint8
		for i := range n {
			if s.Has(i) {
				key |= 1 << uint(i)
			}
		}
		subsets[key] = struct{}{}
	}
	if len(subsets) < 32 {
		t.Fatalf("swarm reached only %d distinct subsets of %d elements, expected many", len(subsets), n)
	}
}
