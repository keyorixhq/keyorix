package diffkit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// --- toy implementations used to exercise the kit itself ----------------------

// evenImpl accepts an int iff it is even; its "subject" is the input halved.
type evenImpl struct{ name string }

func (e evenImpl) Name() string { return e.name }
func (e evenImpl) Run(_ context.Context, in int) (int, error) {
	if in%2 != 0 {
		return 0, errors.New("odd")
	}
	return in / 2, nil
}

// evenOrThreeImpl is deliberately WRONG relative to evenImpl: it also accepts
// multiples of three. Used for the red proof.
type evenOrThreeImpl struct{ name string }

func (e evenOrThreeImpl) Name() string { return e.name }
func (e evenOrThreeImpl) Run(_ context.Context, in int) (int, error) {
	if in%2 != 0 && in%3 != 0 {
		return 0, errors.New("not even, not /3")
	}
	return in / 2, nil
}

// subjectSkewImpl agrees on accept/reject with evenImpl but returns a different
// subject (input, not input/2). Used to prove subject disagreement is caught.
type subjectSkewImpl struct{ name string }

func (e subjectSkewImpl) Name() string { return e.name }
func (e subjectSkewImpl) Run(_ context.Context, in int) (int, error) {
	if in%2 != 0 {
		return 0, errors.New("odd")
	}
	return in, nil
}

type panicImpl struct{ name string }

func (p panicImpl) Name() string { return p.name }
func (p panicImpl) Run(_ context.Context, in int) (int, error) {
	panic("boom")
}

type hangImpl struct{ name string }

func (h hangImpl) Name() string { return h.name }
func (h hangImpl) Run(ctx context.Context, in int) (int, error) {
	<-ctx.Done() // hang until the per-impl timeout cancels us
	return 0, ctx.Err()
}

func intDecide(o Outcome[int]) Verdict {
	v := DecideFrom(o)
	if o.Decision == DecisionAccept {
		v.Subject = o.Value
	}
	return v
}

// --- the table-driven test of the kit ----------------------------------------

func TestCompare(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name      string
		impls     []Impl[int, int]
		diffs     []DocumentedDiff
		in        int
		wantDiver bool
	}{
		{
			name:      "two equal impls agree (green)",
			impls:     []Impl[int, int]{evenImpl{"a"}, evenImpl{"b"}},
			in:        4,
			wantDiver: false,
		},
		{
			name:      "two equal impls agree on reject (green)",
			impls:     []Impl[int, int]{evenImpl{"a"}, evenImpl{"b"}},
			in:        5,
			wantDiver: false,
		},
		{
			// RED PROOF: two deliberately different impls diverge and are reported.
			name:      "different impls diverge on 9 (red)",
			impls:     []Impl[int, int]{evenImpl{"strict"}, evenOrThreeImpl{"loose"}},
			in:        9, // strict rejects, loose accepts (9%3==0)
			wantDiver: true,
		},
		{
			name:      "different impls still agree where decisions coincide",
			impls:     []Impl[int, int]{evenImpl{"strict"}, evenOrThreeImpl{"loose"}},
			in:        8, // both accept, both subject 4
			wantDiver: false,
		},
		{
			name:      "accept/accept but subject disagrees is a divergence",
			impls:     []Impl[int, int]{evenImpl{"half"}, subjectSkewImpl{"whole"}},
			in:        6, // both accept; subjects 3 vs 6
			wantDiver: true,
		},
		{
			name:  "documented difference suppresses the divergence",
			impls: []Impl[int, int]{evenImpl{"strict"}, evenOrThreeImpl{"loose"}},
			diffs: []DocumentedDiff{{
				ID:     "loose-accepts-multiples-of-three",
				Reason: "loose impl additionally accepts multiples of three; known and tolerated here.",
				Explains: func(vs []Verdict, in any) bool {
					// Only explain the exact shape: strict reject, loose accept, input %3==0.
					return in.(int)%3 == 0 &&
						hasDecision(vs, "strict", DecisionReject) &&
						hasDecision(vs, "loose", DecisionAccept)
				},
			}},
			in:        9,
			wantDiver: false,
		},
		{
			name:      "panic in one impl is a verdict, not a crash",
			impls:     []Impl[int, int]{evenImpl{"ok"}, panicImpl{"boom"}},
			in:        4, // ok accepts, boom panics -> divergence
			wantDiver: true,
		},
		{
			name:      "timeout in one impl is a verdict, not a hang",
			impls:     []Impl[int, int]{evenImpl{"ok"}, hangImpl{"slow"}},
			in:        4,
			wantDiver: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Comparator[int, int]{
				Impls:   tc.impls,
				Timeout: 200 * time.Millisecond,
				Decide:  intDecide,
				Diffs:   tc.diffs,
			}
			diverged, d := c.Compare(ctx, tc.in)
			if diverged != tc.wantDiver {
				t.Fatalf("Compare diverged=%v want %v; detail: %v", diverged, tc.wantDiver, d)
			}
			if diverged && d == nil {
				t.Fatal("diverged true but Divergence is nil")
			}
			if !diverged && d != nil {
				t.Fatalf("diverged false but Divergence non-nil: %v", d)
			}
		})
	}
}

func hasDecision(vs []Verdict, impl string, d Decision) bool {
	for _, v := range vs {
		if v.Impl == impl {
			return v.Decision == d
		}
	}
	return false
}

func TestRunPanicCapture(t *testing.T) {
	t.Parallel()
	o := Run(context.Background(), panicImpl{"p"}, 1, time.Second)
	if o.Decision != DecisionPanic {
		t.Fatalf("got %s, want panic", o.Decision)
	}
	if o.PanicValue == nil {
		t.Fatal("PanicValue nil")
	}
}

func TestRunTimeout(t *testing.T) {
	t.Parallel()
	start := time.Now()
	o := Run(context.Background(), hangImpl{"h"}, 1, 50*time.Millisecond)
	if o.Decision != DecisionTimeout {
		t.Fatalf("got %s, want timeout", o.Decision)
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout did not fire promptly")
	}
}

func TestMinimize(t *testing.T) {
	t.Parallel()
	// Diverges whenever the slice contains a 0xFF byte; minimiser should shrink
	// to the single offending byte.
	in := []byte{1, 2, 3, 0xFF, 4, 5, 6, 7}
	stillDiverges := func(b []byte) bool {
		for _, x := range b {
			if x == 0xFF {
				return true
			}
		}
		return false
	}
	got := Minimize(in, ByteCandidates, stillDiverges)
	if len(got) != 1 || got[0] != 0xFF {
		t.Fatalf("Minimize = %v, want [255]", got)
	}
}

func TestMinimizeKeepsDivergence(t *testing.T) {
	t.Parallel()
	// If every candidate stops diverging, Minimize must return the input intact.
	in := []byte{1, 2}
	got := Minimize(in, ByteCandidates, func(b []byte) bool { return len(b) == 2 })
	if len(got) != 2 {
		t.Fatalf("Minimize over-shrank to %v", got)
	}
}
