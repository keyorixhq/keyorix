// named_lock_overlap_sod_test.go — NAMEDLOCK-OVERLAP-2, family "SoD, user and
// machine principals" (docs/design/named-lock-overlap.md): every grant that
// adds to one principal's permissions under sodGrantLockKey row-locks the
// principal and re-runs its separation-of-duties check inside its write
// transaction, so losing the named lock mid-section cannot let two grants
// that are each clean complete a toxic pair together.
//
// Each case: policy roles.assign + secrets.delete. Holder A grants the
// roles.assign half (role 21) to user 1 (or machine 5); its lock is lost after
// its check passed, holder B (another replica) grants the secrets.delete half
// (role 22) and commits, then A writes. A must be refused.
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

const (
	sodUser1Key    = "sod-grant:user:1"
	sodMachine5Key = "sod-grant:machine:5"
)

// newOverlapSoDFixture: roles 21 (roles.assign) and 22 (secrets.delete), a
// policy forbidding both, target user 1, actor 99 (global admin), group 30
// holding role 21 at project 3, and machine identity 5 in project 3. Roles
// 21 and 22 are project-scoped, so every grant is at project 3.
func newOverlapSoDFixture(t *testing.T) *gorm.DB {
	t.Helper()
	db := sqliteDB(t, "overlap_sod.db")
	require.NoError(t, db.AutoMigrate(&models.SoDPolicy{}, &models.AccessRequestApproval{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.Notification{}))
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.delete"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 21, Name: "role-a"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 22, Name: "role-b"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 21, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 22, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.SoDPolicy{Name: "toxic", PermissionA: "roles.assign", PermissionB: "secrets.delete"}).Error)
	for _, u := range []models.User{
		{ID: 1, Username: "target", IsActive: true, AccountState: core.AccountActive},
		{ID: 99, Username: "actor", IsActive: true, AccountState: core.AccountActive},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 30, Name: "assigners"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 30, RoleID: 21, ProjectID: 3}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 3, Name: "p3"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{ID: 5, ProjectID: 3, Name: "m5", State: core.MachineActive}).Error)
	return db
}

// holdsBothHalves reports whether user 1 (directly or through a group) or
// machine 5 holds both role 21 and role 22.
func holdsBothHalves(t *testing.T, db *gorm.DB, machine bool) bool {
	t.Helper()
	var ids []uint
	if machine {
		require.NoError(t, db.Model(&models.MachineIdentityRole{}).Where("machine_identity_id = 5").Pluck("role_id", &ids).Error)
	} else {
		var direct, viaGroup []uint
		require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = 1").Pluck("role_id", &direct).Error)
		require.NoError(t, db.Table("group_roles").Joins("JOIN user_groups ON user_groups.group_id = group_roles.group_id").
			Where("user_groups.user_id = 1").Pluck("group_roles.role_id", &viaGroup).Error)
		ids = append(direct, viaGroup...)
	}
	has := map[uint]bool{}
	for _, id := range ids {
		has[id] = true
	}
	return has[21] && has[22]
}

func TestNamedLockOverlap_SoD_UserAndMachine_NoToxicPair(t *testing.T) {
	t.Parallel()
	ctxB := func(c *core.KeyorixCore, machine bool) func(context.Context) error {
		return func(ctx context.Context) error {
			if machine {
				return c.AssignMachineRole(ctx, 5, 22, core.Scope{ProjectID: 3}, 99, false)
			}
			return c.AssignUserRole(ctx, 99, 1, 22, core.Scope{ProjectID: 3}, false)
		}
	}
	cases := []struct {
		name    string
		key     string
		machine bool
		grantA  func(ctx context.Context, c *core.KeyorixCore) error
	}{
		{"AssignUserRole", sodUser1Key, false, func(ctx context.Context, c *core.KeyorixCore) error {
			return c.AssignUserRole(ctx, 99, 1, 21, core.Scope{ProjectID: 3}, false)
		}},
		{"AssignUserRoleWithExpiry", sodUser1Key, false, func(ctx context.Context, c *core.KeyorixCore) error {
			return c.AssignUserRoleWithExpiry(ctx, 99, 1, 21, core.Scope{ProjectID: 3}, time.Now().Add(time.Hour), false)
		}},
		{"SetUserRoles", sodUser1Key, false, func(ctx context.Context, c *core.KeyorixCore) error {
			return c.SetUserRoles(ctx, 99, 1, []uint{21}, core.Scope{ProjectID: 3}, false)
		}},
		{"AddUserToGroup", sodUser1Key, false, func(ctx context.Context, c *core.KeyorixCore) error {
			return c.AddUserToGroup(ctx, 99, false, 1, 30, 0)
		}},
		{"ApproveAccessRequestWithExpiry", sodUser1Key, false, func(ctx context.Context, c *core.KeyorixCore) error {
			req, err := c.RequestProjectAccess(ctx, 3, 1, "role-a", "need it")
			if err != nil {
				return err
			}
			_, err = c.ApproveAccessRequestWithExpiry(ctx, 3, req.ID, 99, 0, "role-a", 0)
			return err
		}},
		{"AssignMachineRole", sodMachine5Key, true, func(ctx context.Context, c *core.KeyorixCore) error {
			return c.AssignMachineRole(ctx, 5, 21, core.Scope{ProjectID: 3}, 99, false)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newOverlapSoDFixture(t)
			overlap := newLockLossOverlap(t, tc.key, ctxB(core.NewKeyorixCore(store.NewLocalStorage(db)), tc.machine))
			replicaA := core.NewKeyorixCore(overlap.store(store.NewLocalStorage(db)))

			errA := tc.grantA(context.Background(), replicaA)
			t.Logf("holder A: %v; holder B: %v", errA, overlap.secondErr)
			overlap.requireFired()

			require.NoError(t, overlap.secondErr, "holder B granted one half alone and must succeed")
			require.False(t, holdsBothHalves(t, db, tc.machine),
				"holder A granted the other half after holder B's grant committed inside A's lost-lock window: the principal holds a toxic pair (A's error: %v)", errA)
			require.Error(t, errA)
			require.True(t, strings.Contains(errA.Error(), "separation-of-duties"), "A is refused by the separation-of-duties check, got: %v", errA)
		})
	}
}
