// stats_snapshot_host_zone_test.go -- SQLITE-UTC-NOWFUNC-1, REVIEW-3868-DEEP-2 F2.
//
// StatsSnapshot.created_at is stamped by GORM's NowFunc, which is UTC. SQLite
// compares it as text, so GetPreviousStatsSnapshot's 20-hour cutoff must be UTC
// too: a host-zone cutoff on a host west of UTC hid a snapshot that is older
// than 20 hours (and east of UTC returned one that is younger).
//
// Run in a subprocess whose time.Local comes from TZ, through the real storage
// factory.
package http

import (
	"context"
	"testing"
	"time"

	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestPreviousStatsSnapshotCutoff_NonUTCHost_SQLite(t *testing.T) {
	const name = "TestPreviousStatsSnapshotCutoff_NonUTCHost_SQLite"
	if _, child := otHostTZChild(t); child {
		previousStatsSnapshotOnThisHost(t)
		return
	}
	for _, zone := range []string{"America/New_York", "Pacific/Kiritimati"} {
		t.Run(zone, func(t *testing.T) {
			loadZone(t, zone)
			runInOTHostTZ(t, name, zone)
		})
	}
}

func previousStatsSnapshotOnThisHost(t *testing.T) {
	cfg, _ := rrStorageConfig(t, "sqlite")
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ctx := context.Background()

	// Explicit UTC CreatedAt: the same stored form NowFunc produces, placed in time.
	const userID = 7
	now := time.Now().UTC()
	old := &models.StatsSnapshot{UserID: userID, TotalSecrets: 1, CreatedAt: now.Add(-22 * time.Hour)}
	// 10h: younger than the cutoff, but older than a +14 host-zone cutoff (UTC-6h).
	recent := &models.StatsSnapshot{UserID: userID, TotalSecrets: 2, CreatedAt: now.Add(-10 * time.Hour)}
	require.NoError(t, st.SaveStatsSnapshot(ctx, old))
	require.NoError(t, st.SaveStatsSnapshot(ctx, recent))

	got, err := st.GetPreviousStatsSnapshot(ctx, userID)
	require.NoError(t, err, "a 22h-old snapshot is older than the 20h cutoff")
	require.Equal(t, old.ID, got.ID, "the previous snapshot is the 22h-old one, not the 10h-old one")
}
