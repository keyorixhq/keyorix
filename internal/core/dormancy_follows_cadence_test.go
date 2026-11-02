package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3459: a standing grant is dormant when what it confers went unused for longer than
// the recertification cadence (recertification.cadence_days, default 90), not a fixed
// 90 days. Boundary per cadence: last used cadence-1 days ago is in use, cadence+1
// days ago is dormant. A shorter and a longer cadence than the old constant both
// move the boundary; the default keeps the old one.
func TestCountDormantRoleGrants_ThresholdFollowsCadence(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	const proj, user, role = uint(7), uint(41), uint(9)
	for _, tc := range []struct {
		cadence int // configured; 0 = unset
		days    int // effective threshold
	}{
		{0, DefaultRecertificationCadenceDays},
		{30, 30},
		{180, 180},
	} {
		for _, off := range []struct {
			ageDays int
			dormant int
		}{
			{tc.days - 1, 0},
			{tc.days + 1, 1},
		} {
			t.Run(fmt.Sprintf("cadence=%d/last_read=%dd_ago", tc.cadence, off.ageDays), func(t *testing.T) {
				ctx := context.Background()
				ms := &MockStorage{}
				ms.On("ListProjectRoleAssignments", ctx, proj).Return([]storage.RoleAssignment{
					{PrincipalType: "user", PrincipalID: user, RoleID: role, ProjectID: proj},
				}, nil)
				lastRead := now.AddDate(0, 0, -off.ageDays)
				ms.On("LastUserSecretReadActivity", ctx, proj, mock.Anything).Return(map[uint]time.Time{user: lastRead}, nil)
				for _, m := range []string{"LastUserSecretWriteActivity", "LastUserRoleManagementActivity", "LastUserSecretDeletionActivity"} {
					ms.On(m, ctx, proj, mock.Anything).Return(map[uint]time.Time{}, nil)
				}

				c := NewKeyorixCore(ms)
				c.now = func() time.Time { return now }
				c.SetRecertificationCadence(tc.cadence)

				cp := &CompliancePosture{}
				perms := map[uint][]*models.Permission{role: {{Name: permSecretsRead}}}
				got := c.countDormantRoleGrants(ctx, proj, cp, perms, map[uint]bool{})
				require.False(t, cp.Degraded, "%v", cp.DegradedReasons)
				assert.Equal(t, off.dormant, got, "a read-tier grant last used %d days ago, cadence %d days", off.ageDays, tc.days)
			})
		}
	}
}
