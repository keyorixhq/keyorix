package middleware

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

func runs(t *testing.T, scheduler, outcome string) float64 {
	t.Helper()
	return testutil.ToFloat64(schedulerRunsTotal.WithLabelValues(scheduler, outcome))
}

func gauge(t *testing.T, g *prometheus.GaugeVec, scheduler string) float64 {
	t.Helper()
	return testutil.ToFloat64(g.WithLabelValues(scheduler))
}

// durationCount returns how many observations the duration histogram has recorded for
// a scheduler. WithLabelValues creates the child if absent, so an untouched scheduler
// reads 0 rather than panicking.
func durationCount(t *testing.T, scheduler string) uint64 {
	t.Helper()
	h := schedulerRunDuration.WithLabelValues(scheduler).(prometheus.Histogram)
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("write histogram: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestRegisterSchedulerInitialisesCountersToZero(t *testing.T) {
	const name = "test_register"
	RegisterScheduler(name)
	for _, outcome := range []string{"success", "failure", "skipped"} {
		if got := runs(t, name, outcome); got != 0 {
			t.Errorf("outcome %q = %v, want 0 after RegisterScheduler", outcome, got)
		}
	}
}

func TestRecordSchedulerRunSuccess(t *testing.T) {
	const name = "test_success"
	nowUnix = func() int64 { return 1000 }
	t.Cleanup(func() { nowUnix = func() int64 { return time.Now().Unix() } })

	RecordSchedulerRun(name, SchedulerSuccess, 250*time.Millisecond)

	if got := runs(t, name, "success"); got != 1 {
		t.Errorf("success counter = %v, want 1", got)
	}
	if got := gauge(t, schedulerLastRun, name); got != 1000 {
		t.Errorf("last_run = %v, want 1000", got)
	}
	if got := gauge(t, schedulerLastSuccess, name); got != 1000 {
		t.Errorf("last_success = %v, want 1000", got)
	}
	if got := durationCount(t, name); got != 1 {
		t.Errorf("duration observations = %d, want 1 for a run", got)
	}
}

func TestRecordSchedulerRunFailureLeavesLastSuccessUntouched(t *testing.T) {
	const name = "test_failure"
	// Establish a prior success at t=1000, then a failure at t=2000.
	nowUnix = func() int64 { return 1000 }
	t.Cleanup(func() { nowUnix = func() int64 { return time.Now().Unix() } })
	RecordSchedulerRun(name, SchedulerSuccess, time.Millisecond)

	nowUnix = func() int64 { return 2000 }
	RecordSchedulerRun(name, SchedulerFailure, time.Millisecond)

	if got := runs(t, name, "failure"); got != 1 {
		t.Errorf("failure counter = %v, want 1", got)
	}
	// last_run advances on any run (success or failure)...
	if got := gauge(t, schedulerLastRun, name); got != 2000 {
		t.Errorf("last_run = %v, want 2000 (failure advances it)", got)
	}
	// ...but last_success stays pinned to the last successful tick.
	if got := gauge(t, schedulerLastSuccess, name); got != 1000 {
		t.Errorf("last_success = %v, want 1000 (failure must not advance it)", got)
	}
}

func TestRecordSchedulerRunSkippedTouchesOnlyCounter(t *testing.T) {
	const name = "test_skipped"
	nowUnix = func() int64 { return 5000 }
	t.Cleanup(func() { nowUnix = func() int64 { return time.Now().Unix() } })

	RecordSchedulerRun(name, SchedulerSkipped, 999*time.Second)

	if got := runs(t, name, "skipped"); got != 1 {
		t.Errorf("skipped counter = %v, want 1", got)
	}
	// A skip is not a run: its lock-probe time must stay out of the duration
	// histogram, and neither timestamp gauge should move (left absent here).
	if got := durationCount(t, name); got != 0 {
		t.Errorf("skipped tick recorded %d duration observation(s), want 0", got)
	}
	if got := gauge(t, schedulerLastRun, name); got != 0 {
		t.Errorf("last_run = %v, want 0 (a skip must not set it)", got)
	}
	if got := gauge(t, schedulerLastSuccess, name); got != 0 {
		t.Errorf("last_success = %v, want 0 (a skip must not set it)", got)
	}
}
