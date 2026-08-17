// server_s28_test.go — Wave 6 low-severity regression: bounded gRPC shutdown.
//
// startGRPCServer used to call grpcServer.GracefulStop() directly, which
// blocks until every in-flight RPC completes with no timeout of its own. A
// client holding open a long-lived/slow streaming RPC (e.g. StreamAuditLogs)
// and never closing it would block that call forever; main()'s outer 30s
// select/time.After is only a whole-process backstop — it logs "Shutdown
// timeout exceeded, forcing exit" and returns, but never interrupts the
// goroutine still stuck inside GracefulStop(), so the in-flight RPC and any
// pending cleanup in that goroutine were abandoned rather than drained
// deterministically the way startHTTPServer's shutdownCtx-bounded
// server.Shutdown(shutdownCtx) already is.
//
// stopGRPCServerWithTimeout (server/main.go) now mirrors that HTTP pattern:
// GracefulStop() runs in a goroutine bounded by a timeout, falling back to
// the forceful Stop() (which cancels every outstanding RPC immediately) if
// the timeout fires first. This is exercised here via a fake
// grpcGracefulStopper rather than a real gRPC listener + blocked RPC, since a
// deliberately-slow GracefulStop() call is what needs to be simulated, not
// gRPC wire behavior itself.
package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// fakeGracefulStopper simulates *grpc.Server's shutdown surface for
// TestStopGRPCServerWithTimeout_S28: GracefulStop() blocks for gracefulDelay
// unless Stop() is called first, mirroring how a real *grpc.Server's
// Stop() call unblocks a GracefulStop() already in progress by forcibly
// cancelling the RPCs it was waiting to drain.
type fakeGracefulStopper struct {
	gracefulDelay time.Duration
	stopCh        chan struct{}
	stopCalled    atomic.Bool
	gracefulDone  atomic.Bool
}

func newFakeGracefulStopper(gracefulDelay time.Duration) *fakeGracefulStopper {
	return &fakeGracefulStopper{gracefulDelay: gracefulDelay, stopCh: make(chan struct{})}
}

func (f *fakeGracefulStopper) GracefulStop() {
	select {
	case <-time.After(f.gracefulDelay):
	case <-f.stopCh:
	}
	f.gracefulDone.Store(true)
}

func (f *fakeGracefulStopper) Stop() {
	f.stopCalled.Store(true)
	close(f.stopCh)
}

// TestStopGRPCServerWithTimeout_S28_CompletesWithinTimeout verifies that when
// GracefulStop() finishes well inside the timeout (the common case — no
// stuck RPCs), stopGRPCServerWithTimeout returns promptly WITHOUT falling
// back to the forceful Stop(). Pins that the fallback isn't triggered
// unconditionally.
func TestStopGRPCServerWithTimeout_S28_CompletesWithinTimeout(t *testing.T) {
	fake := newFakeGracefulStopper(5 * time.Millisecond)

	start := time.Now()
	stopGRPCServerWithTimeout(fake, 2*time.Second)
	elapsed := time.Since(start)

	if fake.stopCalled.Load() {
		t.Fatal("Stop() (forceful fallback) must not be called when GracefulStop() completes before the timeout")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("stopGRPCServerWithTimeout took %v to return after a fast GracefulStop(); expected it to return promptly", elapsed)
	}
}

// TestStopGRPCServerWithTimeout_S28_FallsBackOnTimeout is the regression for
// the finding: it simulates a client holding a long-lived/slow streaming RPC
// open (GracefulStop() blocked indefinitely, standing in for e.g. an open
// StreamAuditLogs stream that never closes) via a gracefulDelay far longer
// than the configured timeout. Before the fix, the equivalent direct
// grpcServer.GracefulStop() call had no bound of its own and would hang for
// the full delay (in production: forever, until main()'s 30s whole-process
// backstop gives up and returns without ever unblocking this goroutine).
//
// With the fix, stopGRPCServerWithTimeout must return within roughly the
// configured timeout (not the full gracefulDelay) and must have called the
// forceful Stop() fallback, proving the bounded-shutdown/fallback logic
// actually fires rather than only existing in the happy path.
func TestStopGRPCServerWithTimeout_S28_FallsBackOnTimeout(t *testing.T) {
	const timeout = 30 * time.Millisecond
	// Far longer than timeout so — absent the fix — this test would hang for
	// the full duration instead of returning at ~timeout.
	fake := newFakeGracefulStopper(10 * time.Second)

	start := time.Now()
	stopGRPCServerWithTimeout(fake, timeout)
	elapsed := time.Since(start)

	if !fake.stopCalled.Load() {
		t.Fatal("Stop() (forceful fallback) must be called when GracefulStop() does not complete before the timeout")
	}
	// Generous upper bound for scheduling jitter under test load — the point
	// is proving this returns in roughly `timeout`, several orders of
	// magnitude before the 10s gracefulDelay would have elapsed on its own.
	if elapsed > 2*time.Second {
		t.Fatalf("stopGRPCServerWithTimeout took %v to return with a %v timeout and a blocked GracefulStop(); it must not wait for the full graceful delay", elapsed, timeout)
	}
}
