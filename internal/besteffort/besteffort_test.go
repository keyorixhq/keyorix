package besteffort

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestRun_Nil_NoFailureRecorded: the common case (fn returns nil) must not
// touch the metric or log anything -- a best-effort step succeeding is not
// an event worth counting.
func TestRun_Nil_NoFailureRecorded(t *testing.T) {
	before := testutil.ToFloat64(failuresTotal.WithLabelValues("t.nil"))
	called := false
	Run(context.Background(), "t.nil", func() error {
		called = true
		return nil
	})
	if !called {
		t.Fatal("Run did not call fn")
	}
	if got := testutil.ToFloat64(failuresTotal.WithLabelValues("t.nil")); got != before {
		t.Fatalf("expected no change to the failures counter, got %v -> %v", before, got)
	}
}

// TestRun_Error_RecordedNotPropagated: a returned error is counted but never
// surfaces back to the caller -- Run itself returns nothing, so there is
// nothing a caller could even check, by construction.
func TestRun_Error_RecordedNotPropagated(t *testing.T) {
	before := testutil.ToFloat64(failuresTotal.WithLabelValues("t.error"))
	Run(context.Background(), "t.error", func() error {
		return errors.New("injected best-effort failure")
	})
	if got := testutil.ToFloat64(failuresTotal.WithLabelValues("t.error")); got != before+1 {
		t.Fatalf("expected the failures counter to increment by 1, got %v -> %v", before, got)
	}
}

// TestRun_Panic_RecoveredAndRecorded is the actual bug class this package
// exists to close: a panic in fn must not escape Run (it would otherwise
// propagate past the caller's own already-successful write and misreport it
// as a failure), and must still be counted exactly like a returned error.
func TestRun_Panic_RecoveredAndRecorded(t *testing.T) {
	before := testutil.ToFloat64(failuresTotal.WithLabelValues("t.panic"))
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped Run: %v", r)
			}
		}()
		Run(context.Background(), "t.panic", func() error {
			panic("injected best-effort panic")
		})
	}()
	if got := testutil.ToFloat64(failuresTotal.WithLabelValues("t.panic")); got != before+1 {
		t.Fatalf("expected the failures counter to increment by 1, got %v -> %v", before, got)
	}
}

// TestRun_CancelledContext_StillCallsFn: Run does not special-case a
// cancelled context -- a best-effort step is expected to still make its
// attempt (e.g. audit emission on a request whose client just disconnected),
// matching the call sites this package consolidates. A caller that wants
// cancellation to skip the step must check ctx.Err() inside fn itself.
func TestRun_CancelledContext_StillCallsFn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	Run(ctx, "t.cancelled", func() error {
		called = true
		return nil
	})
	if !called {
		t.Fatal("Run skipped fn on a cancelled context; it must not special-case cancellation")
	}
}

// TestRunRecover_Panic_RecoveredAndRecorded exercises the async half used by
// a call site that is already running fn in its own goroutine (goSafe's
// shape): deferring RunRecover's returned func must recover a panic raised
// after it, not just one raised inside RunRecover's own call.
func TestRunRecover_Panic_RecoveredAndRecorded(t *testing.T) {
	before := testutil.ToFloat64(failuresTotal.WithLabelValues("t.runrecover.panic"))
	done := make(chan struct{})
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped RunRecover: %v", r)
			}
			close(done)
		}()
		defer RunRecover("t.runrecover.panic")()
		panic("injected goroutine panic")
	}()
	<-done
	if got := testutil.ToFloat64(failuresTotal.WithLabelValues("t.runrecover.panic")); got != before+1 {
		t.Fatalf("expected the failures counter to increment by 1, got %v -> %v", before, got)
	}
}

// TestRunRecover_NoPanic_NoFailureRecorded: RunRecover's deferred func must
// be a no-op when nothing panicked -- it must not itself record a failure
// just because it ran.
func TestRunRecover_NoPanic_NoFailureRecorded(t *testing.T) {
	before := testutil.ToFloat64(failuresTotal.WithLabelValues("t.runrecover.clean"))
	func() {
		defer RunRecover("t.runrecover.clean")()
	}()
	if got := testutil.ToFloat64(failuresTotal.WithLabelValues("t.runrecover.clean")); got != before {
		t.Fatalf("expected no change to the failures counter, got %v -> %v", before, got)
	}
}
