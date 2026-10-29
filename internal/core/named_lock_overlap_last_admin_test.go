// named_lock_overlap_last_admin_test.go — NAMEDLOCK-OVERLAP-1, caller group
// "user deactivation" (docs/design/named-lock-overlap.md): every path that
// deactivates a user re-checks the last-admin guard inside its write
// transaction, so losing lastAdminGuardLockKey mid-section cannot strand the
// install with zero admins.
//
// Each case: two global admins (users 1 and 2). Holder A deactivates user 1;
// its lock is lost after its guard passed, holder B (another replica)
// deactivates user 2 and commits, then A writes. A must be refused.
package core_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// lastAdminGuardKey is core.lastAdminGuardLockKey. A rename makes the harness's
// requireFired fail, never pass silently.
const lastAdminGuardKey = "last-admin-guard"

// newOverlapTwoAdminFixture: users 1 and 2 hold the install's only admin role
// directly, both SCIM-managed; project 3 exists for the migration case.
func newOverlapTwoAdminFixture(t *testing.T) *gorm.DB {
	t.Helper()
	db := sqliteDB(t, "overlap_last_admin.db")
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}))
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	for _, id := range []uint{1, 2} {
		require.NoError(t, db.Create(&models.User{
			ID: id, Username: fmt.Sprintf("admin%d", id), UsernameFolded: fmt.Sprintf("admin%d", id),
			Email: fmt.Sprintf("admin%d@x.io", id), EmailFolded: fmt.Sprintf("admin%d@x.io", id),
			IsActive: true, AccountState: core.AccountActive, ExternalID: fmt.Sprintf("okta|%d", id),
		}).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: id, RoleID: 10}).Error)
	}
	require.NoError(t, db.Create(&models.Project{ID: 3, Name: "p3"}).Error)
	return db
}

// usableAdmin reports whether userID can still act as an admin: not deleted,
// active, and in a login-capable account state.
func usableAdmin(db *gorm.DB, userID uint) bool {
	var u models.User
	if err := db.First(&u, userID).Error; err != nil {
		return false
	}
	return u.IsActive && !core.AccountLoginBlocked(u.ID, u.AccountState)
}

func TestNamedLockOverlap_UserDeactivation_LastAdminSurvives(t *testing.T) {
	t.Parallel()
	no := false
	type op func(ctx context.Context, c *core.KeyorixCore, target, other uint) error
	cases := []struct {
		name       string
		deactivate op
	}{
		{"SuspendUser", func(ctx context.Context, c *core.KeyorixCore, target, other uint) error {
			return c.SuspendUser(ctx, other, target)
		}},
		{"UpdateUser", func(ctx context.Context, c *core.KeyorixCore, target, other uint) error {
			_, err := c.UpdateUser(ctx, &core.UpdateUserRequest{ID: target, ActorID: other, IsActive: &no})
			return err
		}},
		{"DeleteUser", func(ctx context.Context, c *core.KeyorixCore, target, other uint) error {
			return c.DeleteUser(ctx, other, target)
		}},
		{"UpdateSCIMUser", func(ctx context.Context, c *core.KeyorixCore, target, _ uint) error {
			_, err := c.UpdateSCIMUser(ctx, 99, target, nil, nil, &no)
			return err
		}},
		{"DeprovisionSCIMUser", func(ctx context.Context, c *core.KeyorixCore, target, _ uint) error {
			return c.DeprovisionSCIMUser(ctx, 99, target)
		}},
		{"MigrateUserToMachine", func(ctx context.Context, c *core.KeyorixCore, target, other uint) error {
			_, err := c.MigrateUserToMachine(ctx, fmt.Sprintf("admin%d", target), 3, "", fmt.Sprintf("bot%d", target), other, 0, true)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newOverlapTwoAdminFixture(t)
			replicaB := core.NewKeyorixCore(store.NewLocalStorage(db))
			overlap := newLockLossOverlap(t, lastAdminGuardKey, func(ctx context.Context) error {
				return tc.deactivate(ctx, replicaB, 2, 1)
			})
			replicaA := core.NewKeyorixCore(overlap.store(store.NewLocalStorage(db)))

			errA := tc.deactivate(context.Background(), replicaA, 1, 2)
			t.Logf("holder A: %v; holder B: %v", errA, overlap.secondErr)
			overlap.requireFired()

			require.NoError(t, overlap.secondErr, "holder B ran alone with both admins live and must succeed")
			require.False(t, usableAdmin(db, 2), "holder B's deactivation of admin 2 committed")
			require.True(t, usableAdmin(db, 1),
				"holder A deactivated admin 1 after holder B deactivated admin 2 inside A's lost-lock window: no admin is left (A's error: %v)", errA)
			require.Error(t, errA)
			require.True(t, errors.Is(errA, core.ErrLastAdminDeactivation), "A is refused by the last-admin guard, got: %v", errA)
		})
	}
}
