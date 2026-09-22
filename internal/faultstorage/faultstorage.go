// Package faultstorage wraps a real storage.Storage so a fuzz harness can fail or
// panic the Nth call to any of its methods — reads included — and observe how the
// core/handler/gRPC layer above it reacts. It sits one layer above #1951's
// FuzzFaultInjectedOperations, which faults durability seams (files, fsync,
// rename, the SQL driver, KMS) below the storage interface; this package faults
// the interface itself, so it also catches a caller that makes several storage
// calls and mishandles a failure partway through (dropped error, swallowed panic,
// no rollback) — bugs #1951's seam never sees because durability itself worked.
//
// FaultyStorage implements every storage.Storage method explicitly (see
// faulty_storage_generated.go, produced by ./gen from the interface source) rather
// than embedding storage.Storage. Embedding would let the wrapper compile against
// a future interface method it doesn't yet override, silently skipping fault
// injection for it; explicit implementation makes that a build failure instead —
// the same "self-checking invariant, not downstream failure" principle used
// elsewhere in this codebase.
package faultstorage

import (
	"context"
	"sync"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// FaultKind selects how an armed fault manifests when it fires.
type FaultKind int

const (
	// KindNone means no fault is armed (or the target call count hasn't been reached yet).
	KindNone FaultKind = iota
	// KindError returns Spec.Err (or a generic sentinel) in place of the real call,
	// without invoking the real storage method at all.
	KindError
	// KindPanic panics with Spec.Err in place of the real call.
	KindPanic
	// KindEffectThenError invokes the real storage method (so its effect actually
	// happens), discards whatever it returned, and reports Spec.Err instead — the
	// "wrote/committed, then the caller found out about it late" class of fault
	// (goal oracle (d)): a caller may legally end up with either the pre- or
	// post-effect state, never a mix of the two.
	KindEffectThenError
)

func (k FaultKind) String() string {
	switch k {
	case KindError:
		return "error"
	case KindPanic:
		return "panic"
	case KindEffectThenError:
		return "effect-then-error"
	default:
		return "none"
	}
}

// FaultSpec arms exactly one fault: the NthCall'th invocation (1-indexed, across
// the whole operation including any storage.WithTransaction-scoped sub-calls) of
// Method fires Kind using Err.
type FaultSpec struct {
	Method  string
	NthCall int
	Kind    FaultKind
	Err     error
}

// CallRecord is one entry in the wrapper's call log, used by the fuzz harness to
// print a readable trace (RULES: "the harness prints the decoded operation list,
// principals and fault schedule as readable lines") and to confirm a fault fired
// for the reason it claims, not by accident on an unrelated call.
type CallRecord struct {
	Seq    int // 1-indexed, across the whole operation
	Method string
	Fired  bool
	Kind   FaultKind
}

// sharedState is referenced (not copied) by a FaultyStorage and every child
// wrapper created inside WithTransaction, so the Nth-call counter and fired-once
// latch are consistent across the transaction boundary — a fault armed for the
// 2nd call to some method fires on the 2nd call to that method anywhere in the
// operation, whether or not it happens inside a transaction.
type sharedState struct {
	mu      sync.Mutex
	spec    *FaultSpec // nil: no fault armed, wrapper is a pure pass-through
	counts  map[string]int
	fired   bool
	calls   []CallRecord
	nextSeq int
}

// FaultyStorage wraps a real storage.Storage. Every method is implemented
// explicitly (faulty_storage_generated.go) to consult check() before delegating.
type FaultyStorage struct {
	real  storage.Storage
	state *sharedState
}

// var _ storage.Storage = (*FaultyStorage)(nil) makes a storage.Storage method
// added without regenerating faulty_storage_generated.go a build failure, not a
// silent coverage gap — the whole point of not embedding storage.Storage (see the
// package doc comment).
var _ storage.Storage = (*FaultyStorage)(nil)

// NewFaultyStorage wraps real with spec armed (spec may be nil to arm nothing —
// a pure pass-through, used by the harness to run the fault-free prefix and
// suffix of an operation sequence).
func NewFaultyStorage(real storage.Storage, spec *FaultSpec) *FaultyStorage {
	return &FaultyStorage{
		real: real,
		state: &sharedState{
			spec:   spec,
			counts: make(map[string]int),
		},
	}
}

// Fired reports whether the armed fault has fired yet.
func (w *FaultyStorage) Fired() bool {
	w.state.mu.Lock()
	defer w.state.mu.Unlock()
	return w.state.fired
}

// Arm sets spec as the fault to fire (nil disarms) and resets the per-method
// call counters and fired latch, so NthCall counts from THIS point forward —
// not from any earlier pass-through use of the same wrapper. This is what lets
// a caller run an unfaulted "prefix" (setup calls) through the same wrapper and
// world, snapshot state, then arm a fault that only targets calls made from
// here on, matching the fresh-world-per-iteration reproducibility rule while
// still sharing one real backend between prefix and the operation under test.
func (w *FaultyStorage) Arm(spec *FaultSpec) {
	w.state.mu.Lock()
	defer w.state.mu.Unlock()
	w.state.spec = spec
	w.state.fired = false
	w.state.counts = make(map[string]int)
}

// Calls returns a copy of the call log recorded so far, in invocation order.
func (w *FaultyStorage) Calls() []CallRecord {
	w.state.mu.Lock()
	defer w.state.mu.Unlock()
	out := make([]CallRecord, len(w.state.calls))
	copy(out, w.state.calls)
	return out
}

// child wraps a nested storage.Storage (e.g. the transaction-scoped handle
// WithTransaction hands to its callback) sharing this wrapper's fault state, so
// counting and firing stay consistent across the transaction boundary.
func (w *FaultyStorage) child(real storage.Storage) *FaultyStorage {
	return &FaultyStorage{real: real, state: w.state}
}

// check increments the call counter for method and reports whether the armed
// fault fires on this call. It never fires more than once per FaultyStorage
// family (parent + all its transaction-scoped children share state.fired), since
// goal oracle (b)/(c) is about a SINGLE injected failure's effect, not a storm.
func (w *FaultyStorage) check(method string) (fire bool, kind FaultKind, err error) {
	w.state.mu.Lock()
	defer w.state.mu.Unlock()

	w.state.counts[method]++
	w.state.nextSeq++
	seq := w.state.nextSeq

	spec := w.state.spec
	fire = spec != nil && !w.state.fired && spec.Method == method && w.state.counts[method] == spec.NthCall
	if fire {
		w.state.fired = true
		kind = spec.Kind
		err = spec.Err
	}
	w.state.calls = append(w.state.calls, CallRecord{Seq: seq, Method: method, Fired: fire, Kind: kind})
	return fire, kind, err
}

// WithTransaction is hand-written (not generated) because it must re-wrap the
// transaction-scoped storage.Storage its callback receives, so a fault armed for
// a method called only inside the transaction still fires. Mirrors the pattern
// already used by internal/core/mfa_atomicity_test.go's failingStorage.
func (w *FaultyStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	fire, kind, injected := w.check("WithTransaction")
	if fire {
		switch kind {
		case KindPanic:
			panic(injected)
		case KindError:
			return injected
		case KindEffectThenError:
			_ = w.real.WithTransaction(ctx, func(tx storage.Storage) error {
				return fn(w.child(tx))
			})
			return injected
		}
	}
	return w.real.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(w.child(tx))
	})
}
