// audit_owed_metrics.go — Prometheus view of owed audit rows (audit_owed.go).
//
// keyorix_audit_owed_pending is the number of owed audit rows (every owed revocation,
// not only suspend and degraded break-glass) not yet backfilled: the audit log refused a write after the action had
// taken effect, and the pending_audit_events record is still waiting for
// BackfillPendingAuditEvents.
// Zero is the normal state. It is the same count GET /api/v1/system/info shows to
// system.write holders, so it registers on internal/protectedmetrics (served only at
// the authenticated GET /api/v1/admin/scheduler-metrics), not on public /metrics: it
// tells an anonymous reader that the audit log has been failing.
//
// keyorix_audit_owed_oldest_pending_age_seconds is the age of the oldest such row (0
// when none): the count cannot tell a row that is merely delayed from one that is
// stuck, the age can.
//
// Both are read from the database at scrape time, so they are cluster-wide and the
// same on every replica. A value that cannot be read (store down, read past the
// timeout) is reported as NaN (unknown), never as 0 or a stale value, and
// keyorix_audit_owed_metric_scrape_errors_total counts each failed read so the outage
// itself is alertable (KeyorixAuditOwedMetricUnreadable). No alert fires on the NaN.
package core

import (
	"context"
	"math"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
)

// owedAuditScrapeTimeout bounds the database read made on behalf of one scrape.
const owedAuditScrapeTimeout = 3 * time.Second

// owedAuditMetricSource is the core the gauge reads through; set by
// PublishOwedAuditMetric. Unset (a process that never published) reads as unknown.
var owedAuditMetricSource atomic.Pointer[KeyorixCore]

func init() {
	protectedmetrics.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "keyorix_audit_owed_pending",
		Help: "Number of owed audit rows (every owed revocation, not only suspend and degraded break-glass) not yet backfilled (the audit log refused the write after the action took effect). 0 is normal; NaN means the count could not be read. Cluster-wide; alert when above 0 for 10 minutes.",
	}, func() float64 {
		c := owedAuditMetricSource.Load()
		if c == nil {
			return math.NaN()
		}
		ctx, cancel := context.WithTimeout(context.Background(), owedAuditScrapeTimeout)
		defer cancel()
		n, err := c.storage.CountPendingAuditEvents(ctx)
		if err != nil {
			owedAuditScrapeErrors.Add(1)
			return math.NaN()
		}
		return float64(n)
	}))

	protectedmetrics.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "keyorix_audit_owed_oldest_pending_age_seconds",
		Help: "Age in seconds of the oldest owed audit row still not backfilled (0 when none is pending, so 0 is normal). The count alone cannot tell a delayed row from a stuck one; this can. NaN means the age could not be read (see keyorix_audit_owed_metric_scrape_errors_total), never 0. Cluster-wide; warn above 1 hour, critical above 24 hours.",
	}, func() float64 {
		c := owedAuditMetricSource.Load()
		if c == nil {
			return math.NaN()
		}
		return c.oldestOwedAuditAgeSeconds()
	}))

	// Counts every scrape-time read of the pending table that failed or timed out, for
	// both gauges above. It is per process and needs no database read, so it still moves
	// while the store is unreachable (the case the gauges answer NaN to).
	protectedmetrics.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "keyorix_audit_owed_metric_scrape_errors_total",
		Help: "Scrape-time reads of the owed audit table (for keyorix_audit_owed_pending and keyorix_audit_owed_oldest_pending_age_seconds) that failed or timed out, per process. The gauges answer NaN meanwhile, never a stale or zero value.",
	}, func() float64 { return float64(owedAuditScrapeErrors.Load()) }))

	// The per-process failure count behind system/info's audit_owed_failures. Unlike the
	// gauge it needs no database read, so it still moves when the pending record could
	// not be written either (the row is then logged as NOT queued for backfill).
	protectedmetrics.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "keyorix_audit_owed_failures_total",
		Help: "Owed audit rows (every owed revocation, e.g. a plain secret suspend) the audit log refused when they were due, per process. The action itself still took effect. Each one is either pending for the backfill or logged as lost (SECURITY log line naming the user and secret).",
	}, func() float64 { return float64(owedAuditFailures.Load()) }))
}

// owedAuditScrapeErrors counts failed or timed-out scrape-time reads, per process.
var owedAuditScrapeErrors atomic.Uint64

// oldestOwedAuditAgeSeconds is the age of the oldest pending_audit_events row, 0 when
// none is pending, NaN when it cannot be read within owedAuditScrapeTimeout (counted in
// owedAuditScrapeErrors). The read is one index seek (OldestPendingAuditEventAt) and
// takes no row lock, so it neither waits for nor blocks the backfill. An age below zero
// (another replica's clock ahead of this one) reads as 0, not as a negative age.
func (c *KeyorixCore) oldestOwedAuditAgeSeconds() float64 {
	ctx, cancel := context.WithTimeout(context.Background(), owedAuditScrapeTimeout)
	defer cancel()
	at, found, err := c.storage.OldestPendingAuditEventAt(ctx)
	if err != nil {
		owedAuditScrapeErrors.Add(1)
		return math.NaN()
	}
	if !found {
		return 0
	}
	return math.Max(0, c.now().Sub(at).Seconds())
}

// PublishOwedAuditMetric makes c the source of keyorix_audit_owed_pending and
// keyorix_audit_owed_oldest_pending_age_seconds. The server calls it once at startup.
func (c *KeyorixCore) PublishOwedAuditMetric() { owedAuditMetricSource.Store(c) }
