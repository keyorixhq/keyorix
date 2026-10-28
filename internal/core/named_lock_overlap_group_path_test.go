// named_lock_overlap_group_path_test.go — NAMEDLOCK-OVERLAP-2, family "group-path
// last admin" (docs/design/named-lock-overlap.md): every group-wide removal
// (membership, group role, group delete, SCIM patch/replace/deprovision, access
// review revoke) re-checks its last-admin guard inside its write transaction,
// so losing its named lock mid-section cannot strand the install, or a
// project, with no administrator.
//
// Each case: two routes to the same admin authority (two groups, one member
// each). Holder A removes route 1; its lock is lost after its guard passed,
// holder B (another replica) removes route 2 and commits, then A writes. A
// must be refused and route 1 must survive.
package core_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// projectAdminGuardKey1 is core.projectAdminGuardLockKey(1).
const projectAdminGuardKey1 = "project-admin-guard:1"

// newOverlapTwoAdminGroupsFixture: groups 10 and 20 each hold role 10 at
// projectID (0: the global admin role; otherwise a roles.assign role at that
// project), with one member each (users 1 and 2).
func newOverlapTwoAdminGroupsFixture(t *testing.T, projectID uint) *gorm.DB {
	t.Helper()
	db := sqliteDB(t, "overlap_group_path.db")
	require.NoError(t, db.AutoMigrate(&models.AccessReviewItem{}, &models.AccessReviewCampaign{}))
	if projectID == 0 {
		require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	} else {
		require.NoError(t, db.Create(&models.Project{ID: projectID, Name: "proj"}).Error)
		require.NoError(t, db.Create(&models.Role{ID: 10, Name: "proj_admin"}).Error)
		require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
	}
	for _, id := range []uint{1, 2} {
		require.NoError(t, db.Create(&models.User{ID: id, Username: []string{"", "a", "b"}[id], IsActive: true, AccountState: core.AccountActive}).Error)
		gid := id * 10
		require.NoError(t, db.Create(&models.Group{ID: gid, Name: []string{"", "group-a", "group-b"}[id]}).Error)
		require.NoError(t, db.Create(&models.GroupRole{GroupID: gid, RoleID: 10, ProjectID: projectID}).Error)
		require.NoError(t, db.Create(&models.UserGroup{UserID: id, GroupID: gid}).Error)
	}
	return db
}

// routeLive reports whether route n (user n through group n*10 holding role
// 10) still confers the authority.
func routeLive(db *gorm.DB, n, projectID uint) bool {
	return !groupGone(db, n*10) && !membershipGone(db, n, n*10) && !groupRoleGone(db, n*10, 10, projectID)
}

func TestNamedLockOverlap_GroupPath_LastAdminSurvives(t *testing.T) {
	t.Parallel()
	// remove removes route n (user n from group n*10, or group n*10's role or
	// the group itself) at projectID.
	type remove func(ctx context.Context, c *core.KeyorixCore, n, projectID uint) error
	cases := []struct {
		name      string
		projectID uint
		key       string
		remove    remove
	}{
		{"RemoveUserFromGroup/global", 0, lastAdminGuardKey, func(ctx context.Context, c *core.KeyorixCore, n, _ uint) error {
			return c.RemoveUserFromGroup(ctx, 99, n, n*10, 0)
		}},
		{"RemoveRoleFromGroup/global", 0, lastAdminGuardKey, func(ctx context.Context, c *core.KeyorixCore, n, _ uint) error {
			return c.RemoveRoleFromGroup(ctx, 99, n*10, 10, core.Scope{})
		}},
		{"DeleteGroup/global", 0, lastAdminGuardKey, func(ctx context.Context, c *core.KeyorixCore, n, _ uint) error {
			return c.DeleteGroup(ctx, 99, n*10)
		}},
		{"DeprovisionSCIMGroup/global", 0, lastAdminGuardKey, func(ctx context.Context, c *core.KeyorixCore, n, _ uint) error {
			return c.DeprovisionSCIMGroup(ctx, 99, n*10)
		}},
		{"PatchSCIMGroup/global", 0, lastAdminGuardKey, func(ctx context.Context, c *core.KeyorixCore, n, _ uint) error {
			_, err := c.PatchSCIMGroup(ctx, 99, n*10, nil, nil, []uint{n})
			return err
		}},
		{"ReplaceSCIMGroup/global", 0, lastAdminGuardKey, func(ctx context.Context, c *core.KeyorixCore, n, _ uint) error {
			_, err := c.ReplaceSCIMGroup(ctx, 99, n*10, []string{"", "group-a", "group-b"}[n], nil)
			return err
		}},
		{"RemoveUserFromGroup/project", 1, lastAdminGuardKey, func(ctx context.Context, c *core.KeyorixCore, n, _ uint) error {
			return c.RemoveUserFromGroup(ctx, 99, n, n*10, 0)
		}},
		{"DeleteGroup/project", 1, lastAdminGuardKey, func(ctx context.Context, c *core.KeyorixCore, n, _ uint) error {
			return c.DeleteGroup(ctx, 99, n*10)
		}},
		{"RemoveRoleFromGroup/project", 1, projectAdminGuardKey1, func(ctx context.Context, c *core.KeyorixCore, n, projectID uint) error {
			return c.RemoveRoleFromGroup(ctx, 99, n*10, 10, core.Scope{ProjectID: projectID})
		}},
		{"RevokeAccessReviewGrant/group/project", 1, projectAdminGuardKey1, func(ctx context.Context, c *core.KeyorixCore, n, projectID uint) error {
			return c.RevokeAccessReviewGrant(ctx, 99, projectID, core.AccessReviewDecision{
				Source: "role", PrincipalType: "group", PrincipalID: n * 10, RoleID: 10,
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newOverlapTwoAdminGroupsFixture(t, tc.projectID)
			replicaB := core.NewKeyorixCore(store.NewLocalStorage(db))
			overlap := newLockLossOverlap(t, tc.key, func(ctx context.Context) error {
				return tc.remove(ctx, replicaB, 2, tc.projectID)
			})
			replicaA := core.NewKeyorixCore(overlap.store(store.NewLocalStorage(db)))

			errA := tc.remove(context.Background(), replicaA, 1, tc.projectID)
			t.Logf("holder A: %v; holder B: %v", errA, overlap.secondErr)
			overlap.requireFired()

			require.NoError(t, overlap.secondErr, "holder B ran alone with both routes live and must succeed")
			require.False(t, routeLive(db, 2, tc.projectID), "holder B's removal of route 2 committed")
			require.True(t, routeLive(db, 1, tc.projectID),
				"holder A removed route 1 after holder B removed route 2 inside A's lost-lock window: no administrator is left (A's error: %v)", errA)
			require.True(t, isGuardRefusal(errA), "A is refused by the last-admin guard, got: %v", errA)
		})
	}
}
