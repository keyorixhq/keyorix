package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// TestRunScheduler_TickPanicIsRecovered pins #314's defense-in-depth half: a
// panic inside a scheduler job's tick function must never crash the process.
// Before this fix, runScheduler's goroutine had no recover() at all, so ANY
// panic (the now-fixed nil *APIError dereference, or any future bug) would
// take down the whole server — and would crash again on the next tick after
// restart if the underlying condition persisted, a repeated-crash DoS from
// ordinary operational noise.
func TestRunScheduler_TickPanicIsRecovered(t *testing.T) {
	var ticks atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runScheduler(ctx, "test-panicking-job", 10*time.Millisecond, func() middleware.SchedulerOutcome {
		n := ticks.Add(1)
		if n == 1 {
			panic("simulated tick panic")
		}
		return middleware.SchedulerSuccess
	})

	// The first tick (immediate, on startup) panics. If unrecovered, the whole
	// test binary would crash here rather than reaching this assertion. Wait for
	// a second tick (from the ticker) to prove the goroutine survived the panic
	// and kept running on schedule.
	deadline := time.Now().Add(2 * time.Second)
	for ticks.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ticks.Load() < 2 {
		t.Fatalf("scheduler goroutine did not survive the panic — got %d ticks, want >= 2", ticks.Load())
	}
}
