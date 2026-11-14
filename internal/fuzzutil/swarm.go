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
// DENSITY-EXPONENT scheme (chosen after measuring a naive per-bit mask). A naive
// "element i enabled iff bit (i mod 64) set" mask forces a density of ~50% for
// any alphabet larger than 64, because a random 64-bit value almost always has
// popcount near 32 — so it NEVER produces the small subsets that give swarm its
// power on a large alphabet (the SW1 report has the measurement that motivated
// this). Instead:
//
//   - The low 4 bits of the mask select a density exponent d in 0..15; the
//     remaining bits are a salt. Alphabet index i is ENABLED iff
//     splitmix64(salt ^ i) is divisible by 2^d. d==0 keeps every element
//     (density 1); each increment halves the expected density, so d==5 keeps
//     ~1/32 of the alphabet. This yields subsets whose size varies widely across
//     executions — including the small subsets swarm needs — for ANY alphabet
//     size, small or large.
//   - mask == all-ones (^uint64(0)) enables EVERY element (an explicit special
//     case). Every pre-swarm seed therefore keeps its exact meaning when the
//     all-ones mask is prepended to it: "all operations available", i.e. the
//     uniform generator. (A mask whose low nibble is 0 also yields density 1;
//     that is harmless — it is simply another full-alphabet execution.)
//   - The enabled set is NEVER empty: if the chosen density selects no element
//     (common for a high exponent against a small alphabet), Swarm falls back to
//     the FULL alphabet. An empty alphabet would make a fuzz execution a no-op,
//     which is never what a caller wants and would silently waste the execution.
//
// Swarm is a value type and is safe to copy; it holds no pointers to mutable
// state and performs no allocation after construction beyond the membership
// slice.

// splitmix64 is a fast, well-distributed finalizer used to decide per-element
// membership deterministically from the salt and the index.
func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// Swarm is a decoded feature mask over an alphabet of a fixed size.
type Swarm struct {
	mask    uint64
	n       int
	enabled []int  // sorted enabled alphabet indices, len >= 1 for n > 0
	member  []bool // member[i] == true iff index i is enabled; len == n
	full    bool   // true when every element is enabled (all-ones, density 1, or empty-fallback)
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
	if mask == ^uint64(0) {
		s.markFull()
		return s
	}
	d := uint(mask & 0xF)
	salt := mask >> 4
	modMask := (uint64(1) << d) - 1 // d==0 -> 0 -> every element passes (density 1)
	for i := range n {
		if splitmix64(salt^uint64(i))&modMask == 0 {
			s.member[i] = true
			s.enabled = append(s.enabled, i)
		}
	}
	switch {
	case len(s.enabled) == 0:
		// Never-empty: fall back to the full alphabet.
		s.markFull()
	case len(s.enabled) == n:
		s.full = true
	}
	return s
}

func (s *Swarm) markFull() {
	s.full = true
	s.enabled = make([]int, s.n)
	for i := range s.n {
		s.enabled[i] = i
		s.member[i] = true
	}
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
// enabled set. It is the swarm-aware replacement for `raw % n`. With an all-ones
// mask the enabled set is the whole alphabet in order, so Pick(raw) == raw % n —
// the original uniform selection. Negative selectors are handled.
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

// Mask returns the raw mask this Swarm was built from; useful for logging which
// features an execution ran with.
func (s Swarm) Mask() uint64 { return s.mask }

// IsFull reports whether every alphabet element is enabled — because the mask
// was all-ones, selected density 1, or an empty selection fell back to the full
// alphabet. Callers logging swarm diversity use this to tell a genuine
// "all features" execution from a restricted one.
func (s Swarm) IsFull() bool { return s.full }
