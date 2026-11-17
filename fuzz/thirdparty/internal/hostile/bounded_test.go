package hostile

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type recTB struct {
	mu   sync.Mutex
	errs []string
	logs []string
}

func (r *recTB) Helper() {}
func (r *recTB) Errorf(f string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, fmt.Sprintf(f, a...))
}
func (r *recTB) Logf(f string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, fmt.Sprintf(f, a...))
}

const lim = 150 * time.Millisecond

func gapOf(d time.Duration) func() time.Duration { return func() time.Duration { return d } }

func TestWaitBounded_ReturnsQuietlyWhenDone(t *testing.T) {
	done := make(chan struct{})
	close(done)
	r := &recTB{}
	waitBounded(r, done, lim, "m", gapOf(0))
	if len(r.errs)+len(r.logs) != 0 {
		t.Fatalf("expected silence, got errs=%v logs=%v", r.errs, r.logs)
	}
}

// A hang with a HEALTHY heartbeat must still fail at the first deadline: the sensor must
// not turn real driver hangs into skips.
func TestWaitBounded_HealthyHeartbeatHangFails(t *testing.T) {
	r := &recTB{}
	waitBounded(r, make(chan struct{}), lim, "ORACLE bounded-time", gapOf(10*time.Millisecond))
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "driver hang") {
		t.Fatalf("want one 'driver hang' error, got errs=%v logs=%v", r.errs, r.logs)
	}
}

// Frozen process, call returns once it recovers (inside the grace): STALL, not a failure.
func TestWaitBounded_StallThenReturnIsNotAFailure(t *testing.T) {
	done := make(chan struct{})
	go func() { time.Sleep(lim + lim/2); close(done) }()
	r := &recTB{}
	waitBounded(r, done, lim, "ORACLE bounded-time", gapOf(10*lim))
	if len(r.errs) != 0 || len(r.logs) != 1 || !strings.HasPrefix(r.logs[0], "STALL") {
		t.Fatalf("want one STALL log and no errors, got errs=%v logs=%v", r.errs, r.logs)
	}
}

// Frozen process AND the call never returns: still a failure, one limit later.
func TestWaitBounded_StallThenNeverReturnsFails(t *testing.T) {
	r := &recTB{}
	waitBounded(r, make(chan struct{}), lim, "ORACLE bounded-time", gapOf(10*lim))
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "still had not returned") {
		t.Fatalf("want one 'still had not returned' error, got errs=%v logs=%v", r.errs, r.logs)
	}
}

// The real heartbeat: a normally running process reports a small gap, so a hang is classed
// as a driver hang (this is the path the harnesses actually take).
func TestWaitBounded_RealHeartbeatClassifiesRunningProcessHang(t *testing.T) {
	r := &recTB{}
	WaitBounded(r, make(chan struct{}), 400*time.Millisecond, "ORACLE bounded-time")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "driver hang") {
		t.Fatalf("want 'driver hang', got errs=%v logs=%v", r.errs, r.logs)
	}
}
