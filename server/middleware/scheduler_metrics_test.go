package middleware

import (
	"net/http/httptest"
	"strings"
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

// ── #287: timestamp gauges must not appear on the public /metrics registry ───

func TestSchedulerTimestampGaugesAbsentFromDefaultRegistry(t *testing.T) {
	const name = "test_public_metrics_split"
	RecordSchedulerRun(name, SchedulerSuccess, time.Millisecond)

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather default registry: %v", err)
	}
	for _, mf := range families {
		switch mf.GetName() {
		case "keyorix_scheduler_last_run_timestamp_seconds", "keyorix_scheduler_last_success_timestamp_seconds":
			t.Fatalf("timestamp gauge %q must not be registered on the default (public /metrics) registry", mf.GetName())
		}
	}
}

func TestSchedulerRunsTotalStillOnDefaultRegistry(t *testing.T) {
	// The coarse run-count/duration series are intentionally still public — only the
	// exact-timestamp gauges moved off the default registry.
	const name = "test_public_metrics_present"
	RecordSchedulerRun(name, SchedulerSuccess, time.Millisecond)

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather default registry: %v", err)
	}
	var sawRunsTotal, sawDuration bool
	for _, mf := range families {
		switch mf.GetName() {
		case "keyorix_scheduler_runs_total":
			sawRunsTotal = true
		case "keyorix_scheduler_run_duration_seconds":
			sawDuration = true
		}
	}
	if !sawRunsTotal {
		t.Error("keyorix_scheduler_runs_total should remain on the default registry")
	}
	if !sawDuration {
		t.Error("keyorix_scheduler_run_duration_seconds should remain on the default registry")
	}
}

func TestSchedulerMetricsHandlerServesTimestampGauges(t *testing.T) {
	const name = "test_scheduler_metrics_handler"
	nowUnix = func() int64 { return 4242 }
	t.Cleanup(func() { nowUnix = func() int64 { return time.Now().Unix() } })
	RecordSchedulerRun(name, SchedulerSuccess, time.Millisecond)

	req := httptest.NewRequest("GET", "/api/v1/system/scheduler-metrics", nil)
	rec := httptest.NewRecorder()
	SchedulerMetricsHandler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"keyorix_scheduler_last_run_timestamp_seconds",
		"keyorix_scheduler_last_success_timestamp_seconds",
		name,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scheduler-metrics response missing %q: %s", want, body)
		}
	}
}
