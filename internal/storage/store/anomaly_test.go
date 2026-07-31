package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newAnomalyTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AnomalyAlert{}))
	return NewLocalStorage(db)
}

func boolPtr(b bool) *bool { return &b }

func countAlerts(t *testing.T, ls *LocalStorage) int {
	t.Helper()
	all, err := ls.ListAnomalyAlerts(context.Background(), nil)
	require.NoError(t, err)
	return len(all)
}

// CreateAnomalyAlert is idempotent within the dedup window: re-inserting an
// equivalent alert (same secret/type/actor/IP) is a no-op, but a different IP
// or a later window still produces a fresh alert.
func TestCreateAnomalyAlert_DedupsWithinWindow(t *testing.T) {
	ctx := context.Background()
	ls := newAnomalyTestStore(t)
	now := time.Now().UTC()

	base := func(ip string, at time.Time) *models.AnomalyAlert {
		return &models.AnomalyAlert{
			SecretNodeID: 1, SecretName: "db-pw", AlertType: "new_ip", Severity: "high",
			AccessedBy: "alice", IPAddress: ip, DetectedAt: at,
		}
	}

	// First insert lands.
	require.NoError(t, ls.CreateAnomalyAlert(ctx, base("10.0.0.1", now)))
	assert.Equal(t, 1, countAlerts(t, ls))

	// Identical alert in the same window is suppressed.
	require.NoError(t, ls.CreateAnomalyAlert(ctx, base("10.0.0.1", now)))
	assert.Equal(t, 1, countAlerts(t, ls), "duplicate within window must not insert")

	// Different IP is a distinct alert.
	require.NoError(t, ls.CreateAnomalyAlert(ctx, base("10.0.0.2", now)))
	assert.Equal(t, 2, countAlerts(t, ls))

	// Same identity but a later window (beyond the dedup window) inserts again.
	require.NoError(t, ls.CreateAnomalyAlert(ctx, base("10.0.0.1", now.Add(2*time.Hour))))
	assert.Equal(t, 3, countAlerts(t, ls), "a genuine later recurrence still alerts")
}

// A different alert type for the same access is not deduped against another type.
func TestCreateAnomalyAlert_DistinctTypesNotDeduped(t *testing.T) {
	ctx := context.Background()
	ls := newAnomalyTestStore(t)
	now := time.Now().UTC()

	require.NoError(t, ls.CreateAnomalyAlert(ctx, &models.AnomalyAlert{
		SecretNodeID: 1, AlertType: "new_ip", AccessedBy: "alice", IPAddress: "10.0.0.1", DetectedAt: now,
	}))
	require.NoError(t, ls.CreateAnomalyAlert(ctx, &models.AnomalyAlert{
		SecretNodeID: 1, AlertType: "off_hours", AccessedBy: "alice", IPAddress: "10.0.0.1", DetectedAt: now,
	}))
	assert.Equal(t, 2, countAlerts(t, ls))
}

// ListAnomalyAlerts filters by acknowledged state: nil=all, &true, &false.
func TestListAnomalyAlerts_AcknowledgedFilter(t *testing.T) {
	ctx := context.Background()
	ls := newAnomalyTestStore(t)
	now := time.Now().UTC()

	a1 := &models.AnomalyAlert{SecretNodeID: 1, AlertType: "new_ip", AccessedBy: "alice", IPAddress: "10.0.0.1", DetectedAt: now}
	a2 := &models.AnomalyAlert{SecretNodeID: 2, AlertType: "new_user", AccessedBy: "bob", IPAddress: "10.0.0.2", DetectedAt: now}
	require.NoError(t, ls.CreateAnomalyAlert(ctx, a1))
	require.NoError(t, ls.CreateAnomalyAlert(ctx, a2))
	require.NoError(t, ls.AcknowledgeAnomalyAlert(ctx, a1.ID, 1, now))

	all, err := ls.ListAnomalyAlerts(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, all, 2)

	acked, err := ls.ListAnomalyAlerts(ctx, boolPtr(true))
	require.NoError(t, err)
	require.Len(t, acked, 1)
	assert.Equal(t, a1.ID, acked[0].ID)

	unacked, err := ls.ListAnomalyAlerts(ctx, boolPtr(false))
	require.NoError(t, err)
	require.Len(t, unacked, 1)
	assert.Equal(t, a2.ID, unacked[0].ID)
}

// PrincipalSecretFirstSeen must return the EARLIEST access time per (principal, secret)
// pair, not the latest — repeat reads must not reset "first seen" forward, or a
// principal's long-standing access to a secret would look newly-first-seen on every
// pass (#101).
func TestPrincipalSecretFirstSeen_ReturnsEarliestPerPair(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}))
	ls := NewLocalStorage(db)

	now := time.Now().UTC()
	first := now.Add(-10 * 24 * time.Hour)
	// Three reads of the same (alice, secret 1) pair; the middle two are later than
	// `first` and must not overwrite it as the earliest.
	for _, offset := range []time.Duration{0, 2 * time.Hour, 5 * 24 * time.Hour} {
		require.NoError(t, db.Create(&models.SecretAccessLog{
			SecretNodeID: 1, AccessedBy: "alice", Action: "read", IPAddress: "10.0.0.1",
			AccessTime: first.Add(offset),
		}).Error)
	}
	// A second, unrelated pair.
	require.NoError(t, db.Create(&models.SecretAccessLog{
		SecretNodeID: 2, AccessedBy: "bob", Action: "read", IPAddress: "10.0.0.2",
		AccessTime: now.Add(-1 * time.Hour),
	}).Error)

	got, err := ls.PrincipalSecretFirstSeen(ctx, now.Add(-30*24*time.Hour))
	require.NoError(t, err)
	require.Contains(t, got, "alice")
	require.Contains(t, got["alice"], uint(1))
	assert.WithinDuration(t, first, got["alice"][1], time.Second, "must return the earliest access, not the latest")
	require.Contains(t, got, "bob")
	require.Contains(t, got["bob"], uint(2))

	// The `since` bound excludes pairs whose only activity predates it entirely.
	got, err = ls.PrincipalSecretFirstSeen(ctx, now.Add(-1*time.Minute))
	require.NoError(t, err)
	assert.NotContains(t, got, "alice", "alice's only reads are older than `since`")
	assert.NotContains(t, got, "bob", "bob's only read is older than `since`")
}

// ListSecretAccessLogs must cap the number of rows returned (#101) — otherwise a
// secret read continuously over the query window (a busy CI pipeline, or an attacker
// deliberately hammering reads to bloat the log) makes the anomaly detector, which
// calls this per secret per pass, load an unbounded result set into memory.
func TestListSecretAccessLogs_CapsRowCount(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}))
	ls := NewLocalStorage(db)

	now := time.Now().UTC()
	const overCap = maxSecretAccessLogRows + 50
	rows := make([]models.SecretAccessLog, overCap)
	for i := range rows {
		rows[i] = models.SecretAccessLog{
			SecretNodeID: 1, AccessedBy: "svc", Action: "read", IPAddress: "10.0.0.1",
			AccessTime: now.Add(-time.Duration(overCap-i) * time.Millisecond),
		}
	}
	require.NoError(t, db.CreateInBatches(rows, 1000).Error)

	got, err := ls.ListSecretAccessLogs(ctx, 1, now.Add(-time.Hour))
	require.NoError(t, err)
	assert.Len(t, got, maxSecretAccessLogRows, "result must be capped, not the full over-cap row count")
}
