package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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
	require.NoError(t, ls.AcknowledgeAnomalyAlert(ctx, a1.ID))

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
