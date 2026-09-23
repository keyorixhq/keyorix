package fuzzutil

// StateEdge/StateEdgeGate/PackTuple/TupleSpace are built and verified (unit
// tests, red-proof, `go tool nm` symbol count) but NOT wired into any
// harness in this repo -- measured 2026-09-23 on the core/HTTP sequence
// harnesses (FuzzCoreOperationSequence, FuzzKeyorixHTTPAPISequence): no
// benefit. With StateEdge wired in vs. a red-proofed no-op, distinct
// security-states-reached and rare-tuple time-to-first-reach were
// statistically indistinguishable (and the no-op condition was equal or
// slightly faster on several metrics). Root cause: both harnesses' state
// spaces are shallow enough (360/840 tuples, reached via small-modulo op
// selection on mutated bytes within a single ~30-60 step execution) that
// random sampling enumerates them almost immediately, with or without
// coverage guidance -- the mechanism never got a chance to demonstrate
// corpus-retention benefit. Revisit for a harness with genuinely deep,
// sequence-dependent states (unreachable in one execution by chance alone).
// If revisited, measure state-reach via the fuzzer's own RETAINED CORPUS
// (testdata/fuzz/<Target>/, which only grows on judged-new coverage), not
// via StateReport -- StateReport fires unconditionally on every execution,
// decoupled from coverage novelty, so it can't distinguish "StateEdge
// helped" from "StateEdge is a no-op" (this is exactly what the red-proof
// run demonstrated).
import "fmt"

//go:generate go run ./gen -k 2048 -out stateedge_gen.go

// StateEdgeK is the number of distinct coverage-instrumented cases StateEdge
// dispatches through. Every key a caller passes to StateEdge (directly or via
// a StateEdgeGate) must be < StateEdgeK.
const StateEdgeK = stateEdgeK

// StateEdge makes key a genuinely distinct, coverage-instrumented control-flow
// edge (see the generated stateedge_gen.go). Go's native fuzzer keeps an input
// that reaches a new edge, even when every other edge the input exercises has
// already been seen elsewhere in the corpus. A stateful harness that encodes
// an abstract security-state tuple (principal kind, role state, tenant match,
// ...) into a key and calls StateEdge(key) turns "reached a security state
// the corpus hasn't reached before" into something the fuzzer's own feedback
// loop rewards, even though that tuple doesn't otherwise correspond to any
// branch in the code under test.
//
// key must be < StateEdgeK; StateEdge panics otherwise. An out-of-range key is
// a harness encoding bug (the tuple space grew, or the mixed-radix packing is
// wrong) -- it must fail loudly, not silently stop contributing coverage.
func StateEdge(key uint32) {
	if key >= StateEdgeK {
		panic(fmt.Sprintf("fuzzutil.StateEdge: key %d >= StateEdgeK %d", key, StateEdgeK))
	}
	stateEdgeSwitch(key)
}

// StateEdgeGate makes each key fire StateEdge at most once per gate. Callers
// construct a fresh gate at the start of every fuzz iteration (one input),
// so revisiting the same abstract state multiple times within one input
// doesn't re-trigger the edge -- only the FIRST time an input reaches a given
// state counts as "new" to the fuzzer; a harness must not reward an input for
// merely repeating a state it already reached earlier in the same run.
type StateEdgeGate struct {
	seen []bool
}

// NewStateEdgeGate returns a gate covering the full StateEdgeK key space.
func NewStateEdgeGate() *StateEdgeGate {
	return &StateEdgeGate{seen: make([]bool, StateEdgeK)}
}

// FireOnce calls StateEdge(key) the first time key is seen through this gate
// and is a no-op on every later call with the same key. key must be <
// StateEdgeK; FireOnce panics otherwise, matching StateEdge.
func (g *StateEdgeGate) FireOnce(key uint32) {
	if key >= uint32(len(g.seen)) {
		panic(fmt.Sprintf("fuzzutil.StateEdgeGate.FireOnce: key %d >= %d", key, len(g.seen)))
	}
	if g.seen[key] {
		return
	}
	g.seen[key] = true
	StateEdge(key)
}

// PackTuple encodes a tuple of bucketed axis values into a single
// non-negative key via positional mixed-radix encoding (digits[0] varies
// fastest). sizes[i] is the number of values axis i can take; digits[i] must
// be in [0, sizes[i]). A harness uses this instead of hand-rolling the
// arithmetic itself, so the encoding for every axis combination is exercised
// by ONE tested implementation rather than reproduced (and risking a
// mismatched multiplier) at every call site.
//
// PackTuple panics on a length mismatch or an out-of-range digit -- an
// encoding bug here must fail loudly, not silently alias two different
// tuples onto the same key.
func PackTuple(digits, sizes []int) int {
	if len(digits) != len(sizes) {
		panic(fmt.Sprintf("fuzzutil.PackTuple: len(digits)=%d != len(sizes)=%d", len(digits), len(sizes)))
	}
	key := 0
	mul := 1
	for i, d := range digits {
		if d < 0 || d >= sizes[i] {
			panic(fmt.Sprintf("fuzzutil.PackTuple: digits[%d]=%d out of range [0,%d)", i, d, sizes[i]))
		}
		key += d * mul
		mul *= sizes[i]
	}
	return key
}

// TupleSpace returns the total number of distinct keys PackTuple can produce
// for the given axis sizes (their product) -- callers use it to size and
// bound-check a StateEdge key range at the sizes' declaration site, instead
// of hand-computing (and risking a stale) product.
func TupleSpace(sizes []int) int {
	space := 1
	for _, s := range sizes {
		space *= s
	}
	return space
}
