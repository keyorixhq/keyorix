package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RECERT-BOUND-1: the "last activity" lookups look back over the recertification
// period (the configured cadence; default 90 days; at most 366), and the access
// review report says which window it used.
func TestGenerateProjectAccessReview_LooksBackOverTheReviewPeriod(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		cadence int
		days    int
	}{
		{"default when unset", 0, 90},
		{"configured 30", 30, 30},
		{"configured 180", 180, 180},
		{"capped at the hard maximum", 5000, storage.ActivityLookbackMaxDays},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const proj = uint(2)
			ctx := context.Background()
			ms := &MockStorage{}
			ms.On("ListProjectRoleAssignments", ctx, proj).Return([]storage.RoleAssignment{}, nil)
			ms.On("ListProjectMachineRoleAssignments", ctx, proj).Return([]storage.RoleAssignment{}, nil)
			ms.On("ListSecrets", ctx, mock.Anything).Return([]*models.SecretNode{}, int64(0), nil)
			var gotSince time.Time
			ms.On("LastUserSecretActivity", ctx, proj, mock.Anything).
				Run(func(args mock.Arguments) { gotSince = args.Get(2).(time.Time) }).
				Return(map[uint]time.Time{}, nil)

			c := NewKeyorixCore(ms)
			c.now = func() time.Time { return now }
			c.SetRecertificationCadence(tc.cadence)

			report, err := c.GenerateProjectAccessReview(ctx, proj)
			require.NoError(t, err)
			assert.Equal(t, tc.days, report.ActivityWindowDays)
			assert.Equal(t, now.AddDate(0, 0, -tc.days), gotSince, "the lookup is bounded by the window start")
		})
	}
}

// Dormancy is judged against the review cadence (#3459; default 90, at most 366), so
// the posture lookups look back exactly that far: older activity cannot change the
// verdict.
func TestCountDormantRoleGrants_LooksBackOverTheDormancyThreshold(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	for cadence, days := range map[int]int{0: 90, 30: 30, 180: 180, 5000: storage.ActivityLookbackMaxDays} {
		const proj = uint(3)
		ctx := context.Background()
		ms := &MockStorage{}
		ms.On("ListProjectRoleAssignments", ctx, proj).Return([]storage.RoleAssignment{}, nil)
		want := now.AddDate(0, 0, -days)
		for _, m := range []string{
			"LastUserSecretReadActivity", "LastUserSecretWriteActivity",
			"LastUserRoleManagementActivity", "LastUserSecretDeletionActivity",
		} {
			ms.On(m, ctx, proj, want).Return(map[uint]time.Time{}, nil).Once()
		}

		c := NewKeyorixCore(ms)
		c.now = func() time.Time { return now }
		c.SetRecertificationCadence(cadence)

		cp := &CompliancePosture{}
		assert.Zero(t, c.countDormantRoleGrants(ctx, proj, cp, map[uint][]*models.Permission{}, map[uint]bool{}))
		assert.False(t, cp.Degraded, "cadence %d: %v", cadence, cp.DegradedReasons)
		ms.AssertExpectations(t) // each lookup called once, with the cadence window start
	}
}
