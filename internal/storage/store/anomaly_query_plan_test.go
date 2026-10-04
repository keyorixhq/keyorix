package store

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// anomalySQLCapture is a gorm logger that records every executed statement (vars inlined),
// so a test can EXPLAIN the exact SQL production code issued instead of a hand-copied
// predicate that could drift from it.
type anomalySQLCapture struct {
	logger.Interface
	mu   sync.Mutex
	stmt []string
}

func (c *anomalySQLCapture) LogMode(logger.LogLevel) logger.Interface { return c }
func (c *anomalySQLCapture) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	c.mu.Lock()
	c.stmt = append(c.stmt, sql)
	c.mu.Unlock()
}

func (c *anomalySQLCapture) find(t *testing.T, substrs ...string) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
next:
	for _, s := range c.stmt {
		for _, sub := range substrs {
			if !strings.Contains(s, sub) {
				continue next
			}
		}
		return s
	}
	t.Fatalf("no captured statement contains all of %q; captured: %q", substrs, c.stmt)
	return ""
}

func explainSQLite(t *testing.T, db *gorm.DB, sql string) string {
	t.Helper()
	rows, err := db.Raw("EXPLAIN QUERY PLAN " + sql).Rows()
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &notused, &detail))
		plan = append(plan, detail)
	}
	return strings.Join(plan, " | ")
}

// TestAnomalyQueries_UseTheirIndexes (C-PERF-FIXES, Detected-by: PERF-2) pins that the
// anomaly pass's hot queries are index-served on SQLite: CreateAnomalyAlert's dedup
// count — the single most expensive query in the PERF-2 study — must use
// idx_anomaly_alerts_dedup, and the detector's per-secret and candidate access-log
// reads must use the secret_access_logs indexes rather than full-scanning an
// append-only table written on every secret access. It EXPLAINs the statements
// production code actually issued (captured from gorm), not a copy of the predicate.
// It does not check Postgres plans: the planner there picks a seq scan on tiny test
// tables regardless of indexes, so a plan assertion would be meaningless; the
// indexes themselves are created on both dialects by the same migration
// (TestCompanionIndexes_CreatedOnUpgrade).
func TestAnomalyQueries_UseTheirIndexes(t *testing.T) {
	cap := &anomalySQLCapture{Interface: logger.Discard}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: cap})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AnomalyAlert{}, &models.SecretAccessLog{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, ls.CreateAnomalyAlert(ctx, &models.AnomalyAlert{
		SecretNodeID: 1, AlertType: "new_ip", AccessedBy: "alice", IPAddress: "203.0.113.7", DetectedAt: time.Now(),
	}))
	_, err = ls.ListSecretAccessLogs(ctx, 1, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	_, err = ls.ListSecretIDsAccessedSince(ctx, time.Now().Add(-24*time.Hour))
	require.NoError(t, err)

	cases := []struct {
		name      string
		stmt      []string
		wantIndex string
	}{
		{"CreateAnomalyAlert dedup count", []string{"count(*)", "anomaly_alerts", "alert_type"}, "idx_anomaly_alerts_dedup"},
		{"ListSecretAccessLogs per-secret range", []string{"secret_access_logs", "secret_node_id =", "ORDER BY"}, "idx_secret_access_logs_secret_time"},
		{"ListSecretIDsAccessedSince candidate scan", []string{"DISTINCT +secret_node_id", "secret_access_logs"}, "idx_secret_access_logs_access_time"},
	}
	for _, c := range cases {
		plan := explainSQLite(t, db, cap.find(t, c.stmt...))
		require.Contains(t, plan, c.wantIndex, "%s must be served by %s; plan: %s", c.name, c.wantIndex, plan)
	}
}
