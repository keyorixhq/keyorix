package store

// TZ-RESIDUE-1 item 2 (#3914), sweep: the Purge*Before helpers bind the caller's cutoff against
// deleted_at, which is UTC text on SQLite. A host-zone cutoff mis-ordered by the zone offset: west
// of UTC a row past the retention window survived, east of UTC a row still inside it was
// hard-deleted. The helpers now normalise the cutoff; the other normalised readers are held by
// TestEveryStoreTimeBindIsUTC (internal/core/guards).
//
// The cutoff is modelled with time.LoadLocation: no test assigns time.Local.

import (
	"context"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestPurgeDeletedEnvironmentsBeforeBindsCutoffAsUTC(t *testing.T) {
	deletedAt := time.Date(2026, 6, 12, 20, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		zone   string
		cutoff time.Time
		purged int64
	}{
		{"America/Los_Angeles", deletedAt.Add(time.Minute), 1},
		{"America/Los_Angeles", deletedAt.Add(-time.Minute), 0},
		{"Asia/Tokyo", deletedAt.Add(time.Minute), 1},
		{"Asia/Tokyo", deletedAt.Add(-time.Minute), 0},
	} {
		zone, err := time.LoadLocation(tc.zone)
		require.NoError(t, err, "load %s from the embedded zone database", tc.zone)
		t.Run(tc.zone+"/"+tc.cutoff.Format(time.RFC3339), func(t *testing.T) {
			ctx := context.Background()
			ls := newRestoreTestStore(t)
			proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
			require.NoError(t, err)
			env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
			require.NoError(t, err)
			require.NoError(t, ls.db.Unscoped().Model(&models.Environment{}).Where("id = ?", env.ID).
				Update("deleted_at", deletedAt).Error)

			n, err := ls.PurgeDeletedEnvironmentsBefore(ctx, tc.cutoff.In(zone))
			require.NoError(t, err)
			require.Equal(t, tc.purged, n)
		})
	}
}
