package fuzzutil

import (
	"fmt"
	"os"
	"path/filepath"
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

func withFrozen(t *testing.T, d time.Duration) {
	t.Helper()
	old := frozenSinceFn
	frozenSinceFn = func(time.Time) time.Duration { return d }
	t.Cleanup(func() { frozenSinceFn = old })
}

func TestWait_QuietWhenDone(t *testing.T) {
	ch := make(chan struct{})
	close(ch)
	if _, ok, fz := Wait(ch, lim); !ok || fz != 0 {
		t.Fatalf("ok=%v frozen=%v", ok, fz)
	}
}

// A hang while the process runs must still fail at the first deadline.
func TestWaitBounded_RunningProcessHangFails(t *testing.T) {
	withFrozen(t, 10*time.Millisecond)
	r := &recTB{}
	WaitBounded(r, make(chan struct{}), lim, "ORACLE bounded-time")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "driver hang") {
		t.Fatalf("errs=%v logs=%v", r.errs, r.logs)
	}
}

// Frozen process, call returns after it recovers (inside the grace): STALL, not a failure.
func TestWaitBounded_StallThenReturnIsNotAFailure(t *testing.T) {
	withFrozen(t, 10*lim)
	before := StallsRecovered.Load()
	done := make(chan struct{})
	go func() { time.Sleep(lim + lim/2); close(done) }()
	r := &recTB{}
	WaitBounded(r, done, lim, "ORACLE bounded-time")
	if len(r.errs) != 0 || len(r.logs) != 1 || !strings.HasPrefix(r.logs[0], "STALL") {
		t.Fatalf("errs=%v logs=%v", r.errs, r.logs)
	}
	if StallsRecovered.Load() != before+1 {
		t.Fatalf("StallsRecovered not incremented")
	}
}

// Frozen process AND the call never returns: still a failure, one limit later.
func TestWaitBounded_StallThenNeverReturnsFails(t *testing.T) {
	withFrozen(t, 10*lim)
	r := &recTB{}
	start := time.Now()
	WaitBounded(r, make(chan struct{}), lim, "ORACLE bounded-time")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "still had not returned") {
		t.Fatalf("errs=%v logs=%v", r.errs, r.logs)
	}
	if time.Since(start) < 2*lim {
		t.Fatalf("grace period not waited: %s", time.Since(start))
	}
}

// Guard (the central oracle behind ~96 fuzz targets) takes the same two paths.
func TestGuard_RunningProcessHangFails(t *testing.T) {
	withFrozen(t, 0)
	old := GuardTimeout
	GuardTimeout = lim
	t.Cleanup(func() { GuardTimeout = old })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var msg string
	Guard(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, "x", func() { <-release })
	if !strings.Contains(msg, "exceeded") {
		t.Fatalf("Guard did not report a hang on a running process: %q", msg)
	}
}

func TestGuard_StallThenReturnIsNotAFailure(t *testing.T) {
	withFrozen(t, 10*lim)
	old := GuardTimeout
	GuardTimeout = lim
	t.Cleanup(func() { GuardTimeout = old })
	var msg string
	Guard(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, "x", func() { time.Sleep(lim + lim/2) })
	if msg != "" {
		t.Fatalf("a call that returned inside the grace period was reported: %q", msg)
	}
}

// The real monitor: recorded gaps overlap the window as expected, and a normal process
// reports ~0.
func TestFrozenSince_OverlapAndRunningProcess(t *testing.T) {
	startStallMonitor()
	time.Sleep(3 * stallTick)
	if fz := frozenSince(time.Now().Add(-100 * time.Millisecond)); fz > stallFloor/2 {
		t.Fatalf("running process reported frozen %s", fz)
	}
	now := time.Since(stallBase)
	stallMu.Lock()
	save, saveN := stallGaps, stallN
	stallGaps = [stallRing]stallGap{{now - 3*time.Second, now - time.Second}}
	stallN = 1
	stallMu.Unlock()
	t.Cleanup(func() { stallMu.Lock(); stallGaps, stallN = save, saveN; stallMu.Unlock() })
	// window [now-2s, now] overlaps the recorded gap for exactly 1s
	got := frozenSince(stallBase.Add(now - 2*time.Second))
	if got < 900*time.Millisecond || got > 1100*time.Millisecond {
		t.Fatalf("overlap = %s, want ~1s", got)
	}
	// a window entirely after the gap sees nothing
	if got := frozenSince(stallBase.Add(now - 500*time.Millisecond)); got > 100*time.Millisecond {
		t.Fatalf("later window saw %s of an earlier freeze", got)
	}
}

func TestEffectiveElapsed_SubtractsFreeze(t *testing.T) {
	withFrozen(t, 1500*time.Millisecond)
	eff, fz := EffectiveElapsed(time.Now().Add(-2 * time.Second))
	if fz != 1500*time.Millisecond || eff < 400*time.Millisecond || eff > 700*time.Millisecond {
		t.Fatalf("effective=%s frozen=%s", eff, fz)
	}
	// a freeze larger than the window is clamped, never negative
	withFrozen(t, time.Hour)
	if eff, _ := EffectiveElapsed(time.Now().Add(-time.Second)); eff < 0 {
		t.Fatalf("negative effective elapsed %s", eff)
	}
}

func TestLogStall_AppendsLineWhenEnvSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stalls.log")
	t.Setenv(StallLogEnv, path)
	logStall(1234 * time.Millisecond)
	logStall(2 * time.Second)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "frozen=1.234s") || !strings.Contains(lines[1], "frozen=2s") || !strings.Contains(lines[0], "pid=") {
		t.Fatalf("unexpected stall log: %q", b)
	}
	// unset: no file is created
	t.Setenv(StallLogEnv, "")
	logStall(time.Second)
}
