// scheduler_metrics.go — Prometheus instrumentation for the background schedulers.
//
// The server runs a fleet of periodic schedulers (anomaly detection, retention
// purge, auto-rotation, certificate-expiry scan, …) as goroutines in main. Each was
// previously opaque: a tick that errored only left a log line, so there was no way to
// alert on "scheduler X has not succeeded in an hour" or "tick failure rate is rising".
//
// RecordSchedulerRun folds each tick into the default Prometheus registry, which the
// server already exposes via MetricsHandler. Three outcomes are tracked per scheduler:
//
//   - success — the tick ran and completed without error.
//   - failure — the tick ran and returned an error (or the advisory-lock acquisition
//     itself failed).
//   - skipped — the tick did not run this round: in an HA deployment another replica
//     holds the single-writer advisory lock (ADR-039), or a per-job guard (e.g. an
//     active legal hold) deliberately stood the job down. A skipped tick is NOT a
//     failure — a follower replica skips most ticks by design and must not page.
//
// Suggested alerts: page when a scheduler stops succeeding —
//
//	time() - keyorix_scheduler_last_success_timestamp_seconds{scheduler="auto_rotation"} > 3600
//
// or on absence (a scheduler that has never once succeeded since boot):
//
//	absent(keyorix_scheduler_last_success_timestamp_seconds{scheduler="auto_rotation"})
package middleware

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// SchedulerOutcome is the result of a single scheduler tick. Its string value is used
// directly as the Prometheus `outcome` label, so the set is closed and low-cardinality.
type SchedulerOutcome string

const (
	SchedulerSuccess SchedulerOutcome = "success"
	SchedulerFailure SchedulerOutcome = "failure"
	SchedulerSkipped SchedulerOutcome = "skipped"
)

var (
	schedulerRunsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyorix_scheduler_runs_total",
		Help: "Background scheduler ticks, by scheduler name and outcome (success|failure|skipped).",
	}, []string{"scheduler", "outcome"})

	schedulerRunDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "keyorix_scheduler_run_duration_seconds",
		Help:    "Duration of scheduler ticks that actually ran (success or failure), by scheduler name.",
		Buckets: prometheus.DefBuckets,
	}, []string{"scheduler"})

	schedulerLastRun = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "keyorix_scheduler_last_run_timestamp_seconds",
		Help: "Unix time of the last tick that actually ran (success or failure; not a skip), by scheduler name.",
	}, []string{"scheduler"})

	schedulerLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "keyorix_scheduler_last_success_timestamp_seconds",
		Help: "Unix time of the last successful tick, by scheduler name.",
	}, []string{"scheduler"})

	// nowUnix is overridable in tests; production uses the wall clock.
	nowUnix = func() int64 { return time.Now().Unix() }
)

// RegisterScheduler initialises a scheduler's counter series to zero so dashboards and
// `rate()` queries see an explicit 0 rather than "no data" before the first tick. Call
// once when a scheduler goroutine starts. Idempotent. The timestamp gauges are left
// unset on purpose: a never-run scheduler should read as absent (so `absent(...)`
// alerts fire), not as the epoch.
func RegisterScheduler(name string) {
	for _, outcome := range []SchedulerOutcome{SchedulerSuccess, SchedulerFailure, SchedulerSkipped} {
		schedulerRunsTotal.WithLabelValues(name, string(outcome))
	}
}

// RecordSchedulerRun records the outcome and (for ticks that ran) the duration of a
// single scheduler tick. Skipped ticks bump only the counter — their near-instant
// lock-probe time is not the job's runtime, so it is kept out of the duration
// histogram and the last-run gauge.
func RecordSchedulerRun(name string, outcome SchedulerOutcome, d time.Duration) {
	schedulerRunsTotal.WithLabelValues(name, string(outcome)).Inc()
	if outcome == SchedulerSkipped {
		return
	}
	schedulerRunDuration.WithLabelValues(name).Observe(d.Seconds())
	schedulerLastRun.WithLabelValues(name).Set(float64(nowUnix()))
	if outcome == SchedulerSuccess {
		schedulerLastSuccess.WithLabelValues(name).Set(float64(nowUnix()))
	}
}
