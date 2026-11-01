package store

// TZ-RESIDUE-1 item 2 (#3914): ListUnreviewedBreakGlassActivationsBefore binds the caller's cutoff
// against created_at, which is stored as UTC text on SQLite. Core passes c.now().Add(-window) in
// the host zone, and SQLite compares the bound value's text by wall clock. West of UTC the cutoff's
// wall clock is earlier than the real instant, so an overdue activation dropped out of the posture
// count; east of UTC it is later, so a not-yet-due activation was listed early.
//
// The reader only looks at the zone the cutoff carries, so the host zones are modelled with
// time.LoadLocation: no test assigns time.Local (no_time_local_assignment_guard_test.go).

import (
	"context"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestListUnreviewedBreakGlassActivationsBeforeBindsCutoffAsUTC(t *testing.T) {
	createdAt := time.Date(2026, 6, 12, 20, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		zone    string
		cutoff  time.Time // an instant, expressed in a non-UTC host zone
		listed  bool
		comment string
	}{
		{"America/Los_Angeles", createdAt.Add(time.Minute), true, "overdue by a minute: must be listed west of UTC"},
		{"America/Los_Angeles", createdAt.Add(-time.Minute), false, "not yet due: must not be listed"},
		{"Asia/Tokyo", createdAt.Add(time.Minute), true, "overdue by a minute: must be listed east of UTC"},
		{"Asia/Tokyo", createdAt.Add(-time.Minute), false, "not yet due by a minute: must not be listed east of UTC"},
	} {
		zone, err := time.LoadLocation(tc.zone)
		require.NoError(t, err, "load %s from the embedded zone database", tc.zone)
		t.Run(tc.zone+"/"+tc.comment, func(t *testing.T) {
			ls := newBreakGlassStore(t)
			ctx := context.Background()
			row, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
				ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
			})
			require.NoError(t, err)
			require.NoError(t, ls.db.Model(&models.BreakGlassActivation{}).Where("id = ?", row.ID).
				Update("created_at", createdAt).Error)

			rows, err := ls.ListUnreviewedBreakGlassActivationsBefore(ctx, tc.cutoff.In(zone))
			require.NoError(t, err)

			var ids []uint
			for _, r := range rows {
				ids = append(ids, r.ID)
			}
			if tc.listed {
				require.Contains(t, ids, row.ID, tc.comment)
			} else {
				require.NotContains(t, ids, row.ID, tc.comment)
			}
		})
	}
}
