package core

// keyorix_audit_owed_oldest_pending_age_seconds: the age of the oldest row in
// pending_audit_events, so a delayed owed row cannot become a never-written one unseen.
// Driven through the real LocalStorage and the protected registry with a controlled
// clock, on SQLite here and on PostgreSQL in audit_owed_age_metrics_postgres_test.go.
// The same scenario and plan checks run on both (runOwedAgeScenario, assertOwedAgePlan).

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const owedAgeGaugeName = "keyorix_audit_owed_oldest_pending_age_seconds"

// owedAgeScrape reads the age gauge the way the authenticated endpoint serves it.
func owedAgeScrape(t *testing.T) float64 {
	t.Helper()
	mfs, err := protectedmetrics.Registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == owedAgeGaugeName {
			require.Len(t, mf.GetMetric(), 1)
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal(owedAgeGaugeName + " is not on the protected registry")
	return 0
}

// owedScrapeErrorsScrape reads keyorix_audit_owed_metric_scrape_errors_total.
func owedScrapeErrorsScrape(t *testing.T) float64 {
	t.Helper()
	mfs, err := protectedmetrics.Registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "keyorix_audit_owed_metric_scrape_errors_total" {
			require.Len(t, mf.GetMetric(), 1)
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	t.Fatal("keyorix_audit_owed_metric_scrape_errors_total is not on the protected registry")
	return 0
}

// seedOwedRow inserts a pending row created at the given time (gorm keeps a non-zero
// CreatedAt).
func seedOwedRow(t *testing.T, db *gorm.DB, createdAt time.Time) uint {
	t.Helper()
	p := &models.PendingAuditEvent{EventType: "secret.suspended", Event: "{}", CreatedAt: createdAt, UpdatedAt: createdAt}
	require.NoError(t, db.Create(p).Error)
	return p.ID
}

// owedAgeCore is a core over db whose clock is the returned pointer, published as the
// metric source. Not parallel: the gauge reads through one process-wide source.
func owedAgeCore(t *testing.T, db *gorm.DB, now *time.Time) *KeyorixCore {
	t.Helper()
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.now = func() time.Time { return *now }
	owedAuditMetricSource.Store(c)
	t.Cleanup(func() { owedAuditMetricSource.Store(nil) })
	return c
}

// runOwedAgeScenario is the age contract on a real database: no source reads unknown,
// nothing pending reads 0, the age is that of the OLDEST row, it follows the clock, it
// drops to the next row when the oldest is claimed, and a row dated ahead of this
// replica's clock reads 0 rather than negative.
func runOwedAgeScenario(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.PendingAuditEvent{}))
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	now := t0

	owedAuditMetricSource.Store(nil)
	assert.True(t, math.IsNaN(owedAgeScrape(t)), "no source published: unknown, never a misleading 0")

	c := owedAgeCore(t, db, &now)
	assert.Equal(t, 0.0, owedAgeScrape(t), "nothing owed: 0")

	oldest := seedOwedRow(t, db, t0.Add(-2*time.Hour))
	seedOwedRow(t, db, t0.Add(-10*time.Minute))
	assert.Equal(t, 7200.0, owedAgeScrape(t), "the age of the oldest row, not the newest")

	now = t0.Add(time.Hour)
	assert.Equal(t, 10800.0, owedAgeScrape(t), "it follows the clock")

	claimed, err := c.storage.ClaimPendingAuditEvent(context.Background(), oldest)
	require.NoError(t, err)
	require.True(t, claimed)
	assert.Equal(t, 4200.0, owedAgeScrape(t), "the oldest row is written: the age is the next row's")

	require.NoError(t, db.Where("1 = 1").Delete(&models.PendingAuditEvent{}).Error)
	assert.Equal(t, 0.0, owedAgeScrape(t), "drained: back to 0")

	seedOwedRow(t, db, now.Add(5*time.Minute))
	assert.Equal(t, 0.0, owedAgeScrape(t), "a row stamped ahead of this clock is age 0, not negative")
}

func newOwedAgeSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&models.PendingAuditEvent{}))
	return db
}

func TestOwedAuditOldestPendingAge_SQLite(t *testing.T) {
	runOwedAgeScenario(t, newOwedAgeSQLite(t))
}

// capturedOldestSQL runs OldestPendingAuditEventAt on db and returns the exact SQL and
// bind values it executed, so the plan checks explain the production query rather than
// a copy of it.
func capturedOldestSQL(t *testing.T, db *gorm.DB) (string, []any) {
	t.Helper()
	var sql string
	var vars []any
	name := "capture_owed_oldest"
	require.NoError(t, db.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
		if strings.Contains(tx.Statement.SQL.String(), "pending_audit_events") {
			sql, vars = tx.Statement.SQL.String(), tx.Statement.Vars
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
	_, _, err := store.NewLocalStorage(db).OldestPendingAuditEventAt(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, sql, "the query was not captured")
	return sql, vars
}

// The query must be an index walk on created_at, never a table scan plus sort.
func TestOwedAuditOldestPendingAge_SQLitePlanUsesTheCreatedAtIndex(t *testing.T) {
	db := newOwedAgeSQLite(t)
	for i := range 50 {
		seedOwedRow(t, db, time.Date(2026, 10, 1, 0, i, 0, 0, time.UTC))
	}
	sql, vars := capturedOldestSQL(t, db)
	var plan []string
	rows, err := db.Raw("EXPLAIN QUERY PLAN "+sql, vars...).Rows()
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, parent, notused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &notused, &detail))
		plan = append(plan, detail)
	}
	joined := strings.Join(plan, " | ")
	t.Logf("SQLite plan: %s", joined)
	assert.Contains(t, joined, "idx_pending_audit_events_created_at", "must use the created_at index")
	assert.NotContains(t, joined, "TEMP B-TREE", "must not sort the table")
}

// A read that fails must read unknown (NaN) and count itself, never read 0.
func TestOwedAuditOldestPendingAge_UnreadableIsNaNAndCounted(t *testing.T) {
	db := newOwedAgeSQLite(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	seedOwedRow(t, db, now.Add(-3*time.Hour))
	c := owedAgeCore(t, db, &now)
	require.Equal(t, 10800.0, owedAgeScrape(t))

	// The store goes away (the audit outage itself): the age must not stay at its last value.
	c.storage = hooked(c.storage, &storeHooks{
		OldestPendingAuditEventAt: func(storage.Storage, context.Context) (time.Time, bool, error) {
			return time.Time{}, false, context.DeadlineExceeded
		},
		CountPendingAuditEvents: func(storage.Storage, context.Context) (int64, error) {
			return 0, context.DeadlineExceeded
		},
	})
	// A registry Gather evaluates every gauge, so one scrape is one failed read of each.
	before := owedAuditScrapeErrors.Load()
	assert.True(t, math.IsNaN(owedAgeScrape(t)), "unreadable: unknown, not the stale 10800 and not 0")
	assert.Equal(t, before+2, owedAuditScrapeErrors.Load(), "each failed read (age and count) is counted")
	assert.GreaterOrEqual(t, owedScrapeErrorsScrape(t), float64(before+2), "and the counter is on the protected registry")
	assert.True(t, math.IsNaN(owedPendingScrape(t)), "the count gauge reads unknown too")
}

// A store that hangs must not hang the scrape: the read is bounded by
// owedAuditScrapeTimeout and then counts as an error.
func TestOwedAuditOldestPendingAge_HungStoreIsBoundedAndCounted(t *testing.T) {
	db := newOwedAgeSQLite(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := owedAgeCore(t, db, &now)
	c.storage = hooked(c.storage, &storeHooks{
		OldestPendingAuditEventAt: func(_ storage.Storage, ctx context.Context) (time.Time, bool, error) {
			<-ctx.Done() // a database that never answers
			return time.Time{}, false, ctx.Err()
		},
	})
	before := owedAuditScrapeErrors.Load()
	start := time.Now()
	got := owedAgeScrape(t)
	elapsed := time.Since(start)
	assert.True(t, math.IsNaN(got), "a hung read is unknown")
	assert.Less(t, elapsed, owedAuditScrapeTimeout+2*time.Second, "the scrape is bounded, it does not hang")
	assert.GreaterOrEqual(t, elapsed, owedAuditScrapeTimeout/2, "the read really was waited for, up to the bound")
	assert.Equal(t, before+1, owedAuditScrapeErrors.Load(), "the timed-out read is counted")
}
