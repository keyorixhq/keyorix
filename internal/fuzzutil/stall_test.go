package fuzzutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

// withSelfCaused pins the self-inflicted-freeze verdict, so a grace test does not depend on
// what the rest of the test binary allocated in its window.
func withSelfCaused(t *testing.T, self bool) {
	t.Helper()
	old := selfCausedFn
	selfCausedFn = func(time.Time, time.Duration) (bool, string) { return self, "injected" }
	t.Cleanup(func() { selfCausedFn = old })
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
	withFrozen(t, 10*graceLim)
	withSelfCaused(t, false)
	before := StallsRecovered.Load()
	done := make(chan struct{})
	go func() { time.Sleep(graceLim + graceLim/5); close(done) }()
	r := &recTB{}
	WaitBounded(r, done, graceLim, "ORACLE bounded-time")
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
	withSelfCaused(t, false)
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
	if !strings.Contains(msg, "exceeded") || !strings.Contains(msg, "process was running") {
		t.Fatalf("Guard did not report a hang on a running process: %q", msg)
	}
}

func TestGuard_StallThenReturnIsNotAFailure(t *testing.T) {
	withFrozen(t, 10*graceLim)
	withSelfCaused(t, false)
	old := GuardTimeout
	GuardTimeout = graceLim
	t.Cleanup(func() { GuardTimeout = old })
	var msg string
	Guard(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, "x", func() { time.Sleep(graceLim + graceLim/5) })
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

// OverDeadline: a call within the deadline passes without reading the monitor.
func TestOverDeadline_WithinDeadline(t *testing.T) {
	withFrozen(t, time.Hour) // would be visible if the fast path read it
	if over, why := OverDeadline(time.Now(), time.Second); over {
		t.Fatalf("over=%v why=%q", over, why)
	}
}

// No freeze excuses more than 2x the deadline of wall time, however large it is.
func TestOverDeadline_RawCeiling(t *testing.T) {
	withFrozen(t, time.Hour)
	withSelfCaused(t, false)
	over, why := OverDeadline(time.Now().Add(-2100*time.Millisecond), time.Second)
	if !over || !strings.Contains(why, "2x ceiling") {
		t.Fatalf("over=%v why=%q", over, why)
	}
}

// A genuine (not self-caused) freeze inside the ceiling is forgiven, and logged.
func TestOverDeadline_GenuineFreezeWithinCeiling(t *testing.T) {
	withFrozen(t, 1500*time.Millisecond)
	withSelfCaused(t, false)
	before := StallsRecovered.Load()
	if over, why := OverDeadline(time.Now().Add(-2*time.Second), 1200*time.Millisecond); over {
		t.Fatalf("a 2s call with 1.5s of host freeze failed a 1.2s deadline: %q", why)
	}
	if StallsRecovered.Load() != before+1 {
		t.Fatalf("excused miss not counted")
	}
}

// Only the frozen part is forgiven: running time over the deadline still fails.
func TestOverDeadline_RunningTimeOverDeadlineFails(t *testing.T) {
	withFrozen(t, 300*time.Millisecond)
	withSelfCaused(t, false)
	over, why := OverDeadline(time.Now().Add(-1500*time.Millisecond), time.Second)
	if !over || !strings.Contains(why, "running for") {
		t.Fatalf("over=%v why=%q", over, why)
	}
}

// A freeze the input caused (heap/GC growth) is not forgiven at all.
func TestOverDeadline_SelfInflictedFreezeFails(t *testing.T) {
	withFrozen(t, 1500*time.Millisecond)
	withSelfCaused(t, true)
	over, why := OverDeadline(time.Now().Add(-2*time.Second), 1200*time.Millisecond)
	if !over || !strings.Contains(why, "input caused it") {
		t.Fatalf("over=%v why=%q", over, why)
	}
}

// The real counters: a window that allocates 128 MiB is self-caused, a quiet one is not.
func TestSelfCausedFreeze_RealCounters(t *testing.T) {
	startStallMonitor()
	runtime.GC()
	time.Sleep(3 * stallTick)
	start := time.Now()
	time.Sleep(2 * stallTick)
	if self, sig := selfCausedFreeze(start, time.Second); self {
		t.Fatalf("quiet window reported self-caused: %s", sig)
	}
	start = time.Now()
	b := allocMiB(128)
	if self, sig := selfCausedFreeze(start, time.Second); !self {
		t.Fatalf("128 MiB allocated in the window not reported: %s", sig)
	}
	runtime.KeepAlive(b)
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
