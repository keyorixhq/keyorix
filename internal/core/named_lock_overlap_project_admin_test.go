// named_lock_overlap_project_admin_test.go — NAMEDLOCK-OVERLAP-2, family "last
// project admin" (docs/design/named-lock-overlap.md; was NEEDS ANDREI, closed
// with LockNamedKeyInTx): every direct removal of a user's project roles takes
// projectAdminGuardLockKey with LockNamedKeyInTx in its write transaction and
// re-runs guardLastProjectAdmin through tx, so losing the named lock
// mid-section cannot leave a project with no roles.assign holder.
//
// Each case: users 1 and 2 are project 1's only administrators (role 10,
// roles.assign, granted directly). Holder A removes user 1's; its lock is lost
// after its guard passed, holder B (another replica) removes user 2's and
// commits, then A writes. A must be refused and user 1 must keep the role.
package core_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newOverlapTwoProjectAdminsFixture: project 1, role 10 (roles.assign) held by
// users 1 and 2 at project 1, role 11 (no permission), actor 99 (global
// admin), and break-glass activation 70 recording user 1's grant of role 10.
func newOverlapTwoProjectAdminsFixture(t *testing.T) *gorm.DB {
	t.Helper()
	db := sqliteDB(t, "overlap_project_admin.db")
	require.NoError(t, db.AutoMigrate(&models.BreakGlassActivation{}, &models.AccessReviewItem{}, &models.AccessReviewCampaign{}, &models.SoDPolicy{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 9, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "proj_admin"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 11, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
	for _, u := range []models.User{
		{ID: 1, Username: "a", IsActive: true, AccountState: core.AccountActive},
		{ID: 2, Username: "b", IsActive: true, AccountState: core.AccountActive},
		{ID: 99, Username: "actor", IsActive: true, AccountState: core.AccountActive},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 9}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10, ProjectID: 1}).Error)
	expires := time.Now().Add(time.Hour)
	require.NoError(t, db.Create(&models.BreakGlassActivation{ID: 70, ProjectID: 1, UserID: 1, RoleID: 10, RoleName: "proj_admin",
		State: "active", ExpiresAt: &expires, CreatedAt: time.Now()}).Error)
	return db
}

func holdsProjectAdmin(db *gorm.DB, userID uint) bool {
	var n int64
	_ = db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = 10 AND project_id = 1", userID).Count(&n).Error
	return n == 1
}

func TestNamedLockOverlap_ProjectAdmin_LastAdminSurvives(t *testing.T) {
	t.Parallel()
	removeUser2 := func(ctx context.Context, c *core.KeyorixCore) error {
		return c.RemoveUserRole(ctx, 99, 2, 10, core.Scope{ProjectID: 1})
	}
	cases := []struct {
		name    string
		removeA func(ctx context.Context, c *core.KeyorixCore) error
		removeB func(ctx context.Context, c *core.KeyorixCore) error
	}{
		{"RemoveProjectMember", func(ctx context.Context, c *core.KeyorixCore) error {
			return c.RemoveProjectMember(ctx, 99, 1, 1)
		}, func(ctx context.Context, c *core.KeyorixCore) error {
			return c.RemoveProjectMember(ctx, 99, 1, 2)
		}},
		{"RemoveUserRole", func(ctx context.Context, c *core.KeyorixCore) error {
			return c.RemoveUserRole(ctx, 99, 1, 10, core.Scope{ProjectID: 1})
		}, removeUser2},
		{"SetUserRoles", func(ctx context.Context, c *core.KeyorixCore) error {
			return c.SetUserRoles(ctx, 99, 1, nil, core.Scope{ProjectID: 1}, false)
		}, removeUser2},
		{"SetProjectMemberRole", func(ctx context.Context, c *core.KeyorixCore) error {
			return c.SetProjectMemberRole(ctx, 99, 1, 1, "viewer", false)
		}, removeUser2},
		{"RevokeAccessReviewGrant/user", func(ctx context.Context, c *core.KeyorixCore) error {
			return c.RevokeAccessReviewGrant(ctx, 99, 1, core.AccessReviewDecision{Source: "role", PrincipalType: "user", PrincipalID: 1, RoleID: 10})
		}, removeUser2},
		{"RevokeBreakGlassActivationAtomic", func(ctx context.Context, c *core.KeyorixCore) error {
			return c.RevokeBreakGlassActivationAtomic(ctx, 99, 0, &models.BreakGlassActivation{ID: 70, ProjectID: 1, UserID: 1, RoleID: 10, RoleName: "proj_admin"}, time.Now())
		}, removeUser2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newOverlapTwoProjectAdminsFixture(t)
			replicaB := core.NewKeyorixCore(store.NewLocalStorage(db))
			overlap := newLockLossOverlap(t, projectAdminGuardKey1, func(ctx context.Context) error {
				return tc.removeB(ctx, replicaB)
			})
			replicaA := core.NewKeyorixCore(overlap.store(store.NewLocalStorage(db)))

			errA := tc.removeA(context.Background(), replicaA)
			t.Logf("holder A: %v; holder B: %v", errA, overlap.secondErr)
			overlap.requireFired()

			require.NoError(t, overlap.secondErr, "holder B ran alone with both admins and must succeed")
			require.False(t, holdsProjectAdmin(db, 2), "holder B's removal committed")
			require.True(t, holdsProjectAdmin(db, 1),
				"holder A removed user 1's admin role after holder B removed user 2's inside A's lost-lock window: project 1 has no administrator (A's error: %v)", errA)
			require.Error(t, errA)
			require.True(t, strings.Contains(errA.Error(), "last administrator"), "A is refused by the last-project-admin guard, got: %v", errA)
		})
	}
}
