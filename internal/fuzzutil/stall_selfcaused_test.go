package fuzzutil

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These tests use only the real self-caused check (no injected verdict): the freeze is
// injected, the heap growth is real. They fail on a grace that forgives any freeze.

// graceLim is the limit for tests whose call returns inside the grace period: it returns at
// 1.2x graceLim against a 2x graceLim grace deadline, a 400 ms margin for loaded runners.
const graceLim = 500 * time.Millisecond

// allocMiB allocates n MiB on the heap in 1 MiB objects, so the runtime counts every byte.
// The caller keeps the result alive (runtime.KeepAlive) for as long as it matters.
func allocMiB(n int) [][]byte {
	out := make([][]byte, 0, n)
	for range n {
		out = append(out, make([]byte, 1<<20))
	}
	return out
}

// A memory bomb that thrashes its own process looks frozen to the tick monitor; it must
// still fail at the first deadline instead of getting the grace.
func TestGuard_SelfInflictedFreezeStillFails(t *testing.T) {
	withFrozen(t, 10*graceLim)
	old := GuardTimeout
	GuardTimeout = graceLim
	t.Cleanup(func() { GuardTimeout = old })
	var msg string
	Guard(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, "bomb", func() {
		b := allocMiB(128)
		time.Sleep(graceLim + graceLim/5)
		runtime.KeepAlive(b)
	})
	if !strings.Contains(msg, "exceeded") || !strings.Contains(msg, "self-inflicted") {
		t.Fatalf("a self-inflicted freeze was excused: %q", msg)
	}
}

func TestWait_SelfInflictedFreezeFails(t *testing.T) {
	withFrozen(t, 10*graceLim)
	done := make(chan struct{})
	go func() {
		b := allocMiB(128)
		time.Sleep(graceLim + graceLim/5)
		runtime.KeepAlive(b)
		close(done)
	}()
	r := &recTB{}
	start := time.Now()
	WaitBounded(r, done, graceLim, "ORACLE bounded-time")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "self-inflicted") {
		t.Fatalf("errs=%v logs=%v", r.errs, r.logs)
	}
	if el := time.Since(start); el >= graceLim+graceLim/5 {
		t.Fatalf("grace was waited (%s) for a self-inflicted freeze", el)
	}
}

// The grace forgives only the frozen time: a call that returns inside the grace period but
// ran longer than the limit while the process was running still fails.
func TestWait_SlowButReturnedOverEffectiveBudgetFails(t *testing.T) {
	withFrozen(t, 200*time.Millisecond) // >= graceLim/3, so the grace is given
	done := make(chan struct{})
	go func() { time.Sleep(graceLim + graceLim/2); close(done) }() // runs >= 550 ms of a 500 ms limit
	r := &recTB{}
	WaitBounded(r, done, graceLim, "ORACLE bounded-time")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "over the") {
		t.Fatalf("errs=%v logs=%v", r.errs, r.logs)
	}
}

func TestGuard_SlowButReturnedOverBudgetFails(t *testing.T) {
	withFrozen(t, 200*time.Millisecond)
	old := GuardTimeout
	GuardTimeout = graceLim
	t.Cleanup(func() { GuardTimeout = old })
	var msg string
	Guard(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, "slow", func() { time.Sleep(graceLim + graceLim/2) })
	if !strings.Contains(msg, "exceeded") || !strings.Contains(msg, "over the") {
		t.Fatalf("a call that ran past its limit was excused: %q", msg)
	}
}
