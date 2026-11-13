// Package diffkit is a reusable differential-fuzzing kit.
//
// It compares two or more independent implementations of a single decision
// (typically a security decision: accept/reject plus the value extracted on
// accept). When the implementations disagree in a way that is NOT listed in a
// table of documented, reasoned differences, that disagreement is a reported
// divergence — a lead to triage, not a crash.
//
// The package deliberately imports only the Go standard library so it can be
// copied verbatim into any other module (a third-party library's own repo, a
// throwaway reproducer module, …) without dragging Keyorix along. Nothing here
// knows about Keyorix, JWT, X.509 or SAML; the instances under ../jwtdiff,
// ../certdiff and ../samldiff supply all of that.
//
// Design notes (why it is shaped this way):
//
//   - A panic in one implementation is a *verdict* for that implementation, not
//     a crash of the harness. Run captures panics and reports them as the
//     "panic" decision, so a differential oracle can treat "one side panics, the
//     other accepts" as a divergence worth triaging rather than losing the run.
//   - Each implementation is run under its own timeout. A hang in one side is
//     reported as the "timeout" decision, again a verdict and not a harness hang.
//   - The oracle is intentionally thin: callers reduce a raw (value, error,
//     panic, timeout) Outcome to a Verdict, and the kit only asks "do the
//     Verdicts agree?". That keeps the kit honest about what it does and does
//     not verify — see Compare's doc comment.
package diffkit

import (
	"context"
	"fmt"
	"reflect"
	"time"
)

// Impl is one independent implementation of the decision under test. In is the
// fuzzed input (commonly []byte or a small struct); Out is whatever the
// implementation produces on success (parsed claims, a verified subject, …).
//
// Run MUST honour ctx cancellation where it can, but the kit does not rely on
// it: Run is invoked on its own goroutine and abandoned if it exceeds the
// per-impl timeout (see Run). Run may panic; the kit recovers it.
type Impl[In, Out any] interface {
	// Name is a short, stable identifier used in divergence reports and in the
	// documented-differences table. It must be unique within a comparison.
	Name() string
	// Run executes the decision. A non-nil error means "reject" (the error is
	// the reject reason / error class); a nil error means "accept" with Out the
	// accepted value.
	Run(ctx context.Context, in In) (Out, error)
}

// Decision is the normalised class of an outcome. The first four are produced
// by the kit itself; callers map accept/reject onto a richer Verdict.
type Decision string

const (
	// DecisionAccept means Run returned a nil error.
	DecisionAccept Decision = "accept"
	// DecisionReject means Run returned a non-nil error (and did not panic or
	// time out).
	DecisionReject Decision = "reject"
	// DecisionPanic means Run panicked. PanicValue carries the recovered value.
	DecisionPanic Decision = "panic"
	// DecisionTimeout means Run exceeded its per-impl timeout.
	DecisionTimeout Decision = "timeout"
)

// Outcome is the raw result of running one Impl once.
type Outcome[Out any] struct {
	Impl       string
	Decision   Decision
	Value      Out           // meaningful only when Decision == DecisionAccept
	Err        error         // non-nil only when Decision == DecisionReject
	PanicValue any           // non-nil only when Decision == DecisionPanic
	Duration   time.Duration // wall time Run took (or the timeout, if it hung)
}

// Run executes impl.Run(in) on its own goroutine with a per-impl timeout, and
// turns a panic or a timeout into an Outcome rather than letting it escape.
//
// On timeout the abandoned goroutine keeps running in the background until it
// returns on its own; the kit does not — and cannot, in Go — forcibly kill it.
// Callers that fuzz untrusted code that can wedge a goroutine forever should
// keep timeouts modest so leaked goroutines stay bounded per run.
func Run[In, Out any](parent context.Context, impl Impl[In, Out], in In, timeout time.Duration) Outcome[Out] {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	type result struct {
		val   Out
		err   error
		panic any
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Surface a nil panic as a non-nil sentinel so DecisionPanic is
				// distinguishable from "never ran".
				if r == nil {
					r = "panic(nil)"
				}
				done <- result{panic: r}
			}
		}()
		val, err := impl.Run(ctx, in)
		done <- result{val: val, err: err}
	}()

	select {
	case r := <-done:
		d := time.Since(start)
		switch {
		case r.panic != nil:
			return Outcome[Out]{Impl: impl.Name(), Decision: DecisionPanic, PanicValue: r.panic, Duration: d}
		case r.err != nil:
			return Outcome[Out]{Impl: impl.Name(), Decision: DecisionReject, Err: r.err, Duration: d}
		default:
			return Outcome[Out]{Impl: impl.Name(), Decision: DecisionAccept, Value: r.val, Duration: d}
		}
	case <-ctx.Done():
		return Outcome[Out]{Impl: impl.Name(), Decision: DecisionTimeout, Duration: timeout}
	}
}

// Verdict is the comparable projection of an Outcome used by the oracle. Two
// implementations "agree" iff their Verdicts are deeply equal. Decision carries
// accept/reject/panic/timeout; Subject carries the normalised accepted value
// (and is compared only — by construction it is the zero value unless Decision
// is DecisionAccept, because callers should only populate it then).
type Verdict struct {
	Impl     string
	Decision Decision
	Subject  any
}

// Equal reports whether two verdicts agree on the decision and, when both
// accepted, on the normalised subject. Impl names are intentionally ignored.
func (v Verdict) Equal(o Verdict) bool {
	if v.Decision != o.Decision {
		return false
	}
	if v.Decision == DecisionAccept {
		return reflect.DeepEqual(v.Subject, o.Subject)
	}
	return true
}

// DocumentedDiff is one row of the table of KNOWN, REASONED differences between
// implementations. A divergence that any row Explains is not reported as a
// finding; a divergence that no row explains is. Adding a row is a deliberate
// act that must cite why the difference is acceptable (Reason) — an undocumented
// difference fails, by design.
type DocumentedDiff struct {
	// ID is a short stable slug, e.g. "jwx-stricter-typ-header".
	ID string
	// Reason states, in prose, why this difference is acceptable and which side
	// is right per the spec. It exists to be read by a human reviewing the
	// table; the kit never parses it.
	Reason string
	// Explains reports whether this row accounts for the observed set of
	// verdicts for the given input. It should be as specific as possible so it
	// does not accidentally swallow an unrelated, real divergence.
	Explains func(verdicts []Verdict, in any) bool
}

// Divergence is a reported disagreement that no DocumentedDiff explained.
type Divergence struct {
	Input    any
	Verdicts []Verdict
}

func (d *Divergence) String() string {
	s := fmt.Sprintf("divergence on input %v:", d.Input)
	for _, v := range d.Verdicts {
		switch v.Decision {
		case DecisionAccept:
			s += fmt.Sprintf("\n  %-16s accept subject=%v", v.Impl, v.Subject)
		case DecisionReject:
			s += fmt.Sprintf("\n  %-16s reject", v.Impl)
		default:
			s += fmt.Sprintf("\n  %-16s %s", v.Impl, v.Decision)
		}
	}
	return s
}

// Comparator holds everything needed to turn a fuzzed input into a verdict per
// implementation and decide whether the implementations diverge. It is reusable
// across many inputs (and safe for concurrent use as long as the Impls are).
type Comparator[In, Out any] struct {
	Impls   []Impl[In, Out]
	Timeout time.Duration
	// Decide reduces a raw Outcome to the comparable Verdict. It is where the
	// instance decides what "the same accepted value" means (e.g. normalise a
	// JWT's claims to the subset both libraries can represent). The kit passes
	// the Outcome; Decide must set Verdict.Decision from it (helper DecideFrom
	// does the mechanical part) and populate Subject on accept.
	Decide func(Outcome[Out]) Verdict
	// Diffs is the table of documented, reasoned differences. May be nil.
	Diffs []DocumentedDiff
}

// DecideFrom is a convenience for Comparator.Decide implementations: it copies
// the kit-owned fields (Impl, Decision) across and leaves Subject for the
// caller to fill on accept.
func DecideFrom[Out any](o Outcome[Out]) Verdict {
	return Verdict{Impl: o.Impl, Decision: o.Decision}
}

// Compare runs every implementation on in and reports a Divergence unless all
// verdicts agree OR a DocumentedDiff explains the disagreement.
//
// What this verifies: that the implementations reach the SAME decision
// (accept/reject/panic/timeout) and, when they all accept, the SAME normalised
// subject. What it does NOT verify: that the shared decision is CORRECT. If
// every implementation agrees on a wrong answer, Compare is silent — a
// differential oracle can only find disagreements, never a shared blind spot.
// It also does not verify anything about inputs on which Decide collapses
// distinct outcomes to the same Verdict; choosing a Decide that over-normalises
// is how a real divergence gets hidden, so keep Subject as faithful as the two
// sides can both represent.
func (c Comparator[In, Out]) Compare(ctx context.Context, in In) (bool, *Divergence) {
	verdicts := make([]Verdict, 0, len(c.Impls))
	for _, impl := range c.Impls {
		o := Run(ctx, impl, in, c.Timeout)
		verdicts = append(verdicts, c.Decide(o))
	}
	if verdictsAgree(verdicts) {
		return false, nil
	}
	for _, d := range c.Diffs {
		if d.Explains != nil && d.Explains(verdicts, in) {
			return false, nil
		}
	}
	return true, &Divergence{Input: in, Verdicts: verdicts}
}

func verdictsAgree(verdicts []Verdict) bool {
	for i := 1; i < len(verdicts); i++ {
		if !verdicts[0].Equal(verdicts[i]) {
			return false
		}
	}
	return true
}
