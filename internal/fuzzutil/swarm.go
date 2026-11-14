package fuzzutil

// Swarm testing (Groce et al., "Swarm Testing", ISSTA 2012) runs each test
// execution over a random SUBSET of the available operation alphabet instead of
// the whole alphabet every time. Uniform generation that always makes every
// operation available under-exercises interactions between operations that mask
// or cancel each other: a bug that only shows up when operation A and operation
// B both occur while operation C never occurs is, in the limit, unreachable by a
// generator that always keeps C available. Disabling a random subset of the
// alphabet per execution makes those "feature A present, feature C absent"
// states ordinary rather than astronomically rare.
//
// Swarm is the reusable decoder of a per-execution "feature mask" (taken from
// the fuzz input, by convention the first fuzz argument) into the subset of an
// operation alphabet that execution may use. It is deliberately tiny and has no
// test-only dependency, matching the rest of this package: it is imported only
// from _test.go files but is ordinary library code.
//
// Mask semantics (chosen so the existing seed corpus keeps its meaning):
//
//   - The alphabet has indices 0..n-1. Alphabet index i is ENABLED iff bit
//     (i mod 64) of the mask is set. For n <= 64 this is a true per-element
//     mask; for n > 64 bits are shared cyclically, which still yields a random
//     subset but no longer an independent per-element choice (documented, not a
//     bug — see SwarmBitsShared).
//   - mask == all-ones (^uint64(0)) enables EVERY element. Every pre-swarm seed
//     therefore keeps its exact meaning when the all-ones mask is prepended to
//     it: "all operations available", i.e. the uniform generator.
//   - The enabled set is NEVER empty: if the mask selects no element of the
//     alphabet (the clearest case being mask == 0, but also any mask whose set
//     bits all fall outside 0..n-1 for n < 64), Swarm falls back to the FULL
//     alphabet. An empty alphabet would make a fuzz execution a no-op, which is
//     never what a caller wants and would silently waste the execution.
//
// Swarm is a value type and is safe to copy; it holds no pointers to mutable
// state and performs no allocation after construction beyond the membership
// slice.

// Swarm is a decoded feature mask over an alphabet of a fixed size.
type Swarm struct {
	mask    uint64
	n       int
	enabled []int  // sorted enabled alphabet indices, len >= 1
	member  []bool // member[i] == true iff index i is enabled; len == n
	full    bool   // true when the mask selected nothing and we fell back to all
}

// NewSwarm decodes mask into the enabled subset of an alphabet of size n.
//
// n <= 0 yields a Swarm whose Len is 0 and whose Pick always returns 0; callers
// with an empty alphabet have nothing to pick and should guard on Len, but the
// zero return keeps a misuse from panicking inside a fuzz worker.
func NewSwarm(mask uint64, n int) Swarm {
	s := Swarm{mask: mask, n: n}
	if n <= 0 {
		return s
	}
	s.member = make([]bool, n)
	for i := range n {
		if mask&(uint64(1)<<(uint(i)%64)) != 0 {
			s.member[i] = true
			s.enabled = append(s.enabled, i)
		}
	}
	if len(s.enabled) == 0 {
		// Never-empty: fall back to the full alphabet. This covers mask == 0 and
		// any mask that happens to select none of the first n bits.
		s.full = true
		s.enabled = make([]int, n)
		for i := range n {
			s.enabled[i] = i
			s.member[i] = true
		}
	}
	return s
}

// Len reports how many alphabet elements are enabled (>= 1 for a non-empty
// alphabet, 0 only when n <= 0).
func (s Swarm) Len() int { return len(s.enabled) }

// Has reports whether alphabet index i is enabled under this mask. Out-of-range
// indices are not enabled.
func (s Swarm) Has(i int) bool {
	if i < 0 || i >= s.n {
		return false
	}
	return s.member[i]
}

// Pick maps an arbitrary selector (e.g. a byte or a 16-bit value drawn from the
// fuzz input) onto one of the ENABLED alphabet indices, uniformly over the
// enabled set. It is the swarm-aware replacement for `raw % n`. Negative
// selectors are handled (Go's % can be negative).
func (s Swarm) Pick(raw int) int {
	l := len(s.enabled)
	if l == 0 {
		return 0
	}
	idx := raw % l
	if idx < 0 {
		idx += l
	}
	return s.enabled[idx]
}

// Enabled returns the sorted slice of enabled alphabet indices. The returned
// slice must not be mutated by the caller.
func (s Swarm) Enabled() []int { return s.enabled }

// Mask returns the raw mask this Swarm was built from (not the fallback result);
// useful for logging which features an execution ran with.
func (s Swarm) Mask() uint64 { return s.mask }

// IsFull reports whether every alphabet element is enabled — either because the
// mask set every relevant bit (the all-ones seed case) or because an empty
// selection fell back to the full alphabet. Callers logging swarm diversity use
// this to tell a genuine "all features" execution from a degenerate one.
func (s Swarm) IsFull() bool { return s.full || len(s.enabled) == s.n }
