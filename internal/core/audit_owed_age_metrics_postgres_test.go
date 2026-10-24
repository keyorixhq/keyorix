package core

// keyorix_audit_owed_oldest_pending_age_seconds on PostgreSQL (KEYORIX_TEST_PG_DSN; a
// skip without it): the same age contract as SQLite, the query plan is an index scan on
// created_at, and the read does not wait on the backfill's row locks (a plain SELECT
// takes none, so it cannot block the backfill either).

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestOwedAuditOldestPendingAge_Postgres(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	runOwedAgeScenario(t, pgOpen(t, dsn))
}

// With sequential scans disabled the planner must still pick the created_at index for
// the production query (on a tiny table it would otherwise prefer a seq scan whatever
// the query shape), and the plan must not sort. It proves an index path exists and is
// the one used for the ORDER BY ... LIMIT 1, which is what keeps the scrape O(log n).
func TestOwedAuditOldestPendingAge_PostgresPlanUsesTheCreatedAtIndex(t *testing.T) {
	db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	require.NoError(t, db.AutoMigrate(&models.PendingAuditEvent{}))
	for i := range 200 {
		seedOwedRow(t, db, time.Date(2026, 10, 1, 0, i, 0, 0, time.UTC))
	}
	require.NoError(t, db.Exec("ANALYZE pending_audit_events").Error)
	sql, vars := capturedOldestSQL(t, db)

	var plan []string
	require.NoError(t, db.Connection(func(tx *gorm.DB) error {
		require.NoError(t, tx.Exec("SET enable_seqscan = off").Error)
		return tx.Raw("EXPLAIN "+sql, vars...).Scan(&plan).Error
	}))
	joined := strings.Join(plan, " | ")
	t.Logf("PostgreSQL plan: %s", joined)
	assert.Contains(t, joined, "idx_pending_audit_events_created_at", "must use the created_at index")
	assert.NotContains(t, joined, "Seq Scan")
	assert.NotContains(t, joined, "Sort")
}

// The backfill claims a row with a DELETE inside the transaction that appends its audit
// row, and holds row locks until that commits. The metric read is a plain SELECT, so
// while such a transaction is open (and while another holds FOR UPDATE on the oldest
// row) the scrape must answer at once, not queue behind it.
func TestOwedAuditOldestPendingAge_PostgresScrapeDoesNotWaitOnBackfillLocks(t *testing.T) {
	db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	require.NoError(t, db.AutoMigrate(&models.PendingAuditEvent{}))
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	now := t0
	oldest := seedOwedRow(t, db, t0.Add(-90*time.Minute))
	seedOwedRow(t, db, t0.Add(-5*time.Minute))
	owedAgeCore(t, db, &now)

	claim := db.Begin()
	require.NoError(t, claim.Error)
	t.Cleanup(func() { _ = claim.Rollback().Error })
	res := claim.Exec("DELETE FROM pending_audit_events WHERE id = ?", oldest) // the claim, uncommitted
	require.NoError(t, res.Error)
	require.EqualValues(t, 1, res.RowsAffected)

	done := make(chan float64, 1)
	go func() { done <- owedAgeScrape(t) }()
	select {
	case got := <-done:
		// The uncommitted claim is invisible to the reader: the row is still owed.
		assert.Equal(t, 5400.0, got, "an in-flight claim does not hide the row")
	case <-time.After(2 * time.Second):
		_ = claim.Rollback() // release the lock so the goroutine can finish
		t.Fatal("the scrape waited on the backfill's row lock")
	}
	require.NoError(t, claim.Commit().Error)
}
