// named_lock_overlap_sod_postgres_test.go — NAMEDLOCK-OVERLAP-2, the PostgreSQL
// half of named_lock_overlap_sod_test.go: both grant transactions open at once,
// on two replicas (overlapPGRun). Replica B starts inside A's grant transaction,
// after A's fence and before A's write; B's fence must wait on the principal's
// row A holds, then B's re-check sees A's committed half and refuses.
//
// SetUserRoles is the case only this test can tell apart: its transaction
// already re-ran the check before NAMEDLOCK-OVERLAP-2, without the row lock,
// so two open transactions both saw the clean state.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedSoDPG: project, roles a (roles.assign) and b (secrets.delete) and a
// policy forbidding both, a target user, a machine identity in the project.
func seedSoDPG(t *testing.T, db *gorm.DB) (proj, roleA, roleB, user, machine uint) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.SoDPolicy{}, &models.MachineIdentity{}, &models.MachineIdentityRole{}))
	p := models.Project{Name: "sod-overlap"}
	require.NoError(t, db.Create(&p).Error)
	var assign models.Permission
	require.NoError(t, db.Where("name = ?", "roles.assign").First(&assign).Error)
	del := models.Permission{Name: "secrets.delete"}
	require.NoError(t, db.Create(&del).Error)
	ra, rb := models.Role{Name: "sod-a"}, models.Role{Name: "sod-b"}
	require.NoError(t, db.Create(&ra).Error)
	require.NoError(t, db.Create(&rb).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: ra.ID, PermissionID: assign.ID}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: rb.ID, PermissionID: del.ID}).Error)
	require.NoError(t, db.Create(&models.SoDPolicy{Name: "toxic", PermissionA: "roles.assign", PermissionB: "secrets.delete"}).Error)
	u := models.User{Username: "sod-target", UsernameFolded: "sod-target", IsActive: true, AccountState: AccountActive}
	require.NoError(t, db.Create(&u).Error)
	m := models.MachineIdentity{ProjectID: p.ID, Name: "sod-m", State: MachineActive}
	require.NoError(t, db.Create(&m).Error)
	return p.ID, ra.ID, rb.ID, u.ID, m.ID
}

func TestNamedLockOverlap_SoD_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	// hookUserGrant starts B at A's direct-grant write (AssignRole), after A's fence.
	hookUserGrant := func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{AssignRole: func(next storage.Storage, ctx context.Context, userID, roleID uint, sc storage.Scope) error {
			start()
			return next.AssignRole(ctx, userID, roleID, sc)
		}}
	}
	cases := []struct {
		name    string
		machine bool
		hookAt  func(start func()) *storagetest.StoreHooks
		grantA  func(ctx context.Context, c *KeyorixCore, proj, role, user, machine uint) error
	}{
		{"AssignUserRole", false, hookUserGrant, func(ctx context.Context, c *KeyorixCore, proj, role, user, _ uint) error {
			return c.AssignUserRole(ctx, 0, user, role, Scope{ProjectID: proj}, false)
		}},
		{"SetUserRoles", false, hookUserGrant, func(ctx context.Context, c *KeyorixCore, proj, role, user, _ uint) error {
			return c.SetUserRoles(ctx, 0, user, []uint{role}, Scope{ProjectID: proj}, false)
		}},
		{"AssignMachineRole", true, func(start func()) *storagetest.StoreHooks {
			// After the fence's row lock, before A's re-check and write.
			return &storagetest.StoreHooks{LockMachineIdentityForUpdate: func(next storage.Storage, ctx context.Context, id uint) (*models.MachineIdentity, error) {
				m, err := next.LockMachineIdentityForUpdate(ctx, id)
				start()
				return m, err
			}}
		}, func(ctx context.Context, c *KeyorixCore, proj, role, _, machine uint) error {
			return c.AssignMachineRole(ctx, machine, role, Scope{ProjectID: proj}, 0, false)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dsn, setupDB := newPGLastAdminSchemaDSN(t)
			proj, roleA, roleB, user, machine := seedSoDPG(t, setupDB)
			closePG(setupDB)

			errA, errB, early := overlapPGRun(t, dsn, tc.hookAt, func(ctx context.Context, c *KeyorixCore) error {
				return tc.grantA(ctx, c, proj, roleA, user, machine)
			}, func(ctx context.Context, c *KeyorixCore) error {
				if tc.machine {
					return c.AssignMachineRole(ctx, machine, roleB, Scope{ProjectID: proj}, 0, false)
				}
				return c.AssignUserRole(ctx, 0, user, roleB, Scope{ProjectID: proj}, false)
			})

			check := pgOpen(t, dsn)
			defer closePG(check)
			var held []uint
			if tc.machine {
				require.NoError(t, check.Model(&models.MachineIdentityRole{}).Where("machine_identity_id = ?", machine).Pluck("role_id", &held).Error)
			} else {
				require.NoError(t, check.Model(&models.UserRole{}).Where("user_id = ?", user).Pluck("role_id", &held).Error)
			}
			require.NoError(t, errA, "replica A held the principal's row first and must win")
			require.False(t, early, "replica B's grant transaction must wait for A's (it finished while A's was open: %v)", errB)
			require.Len(t, held, 1, "two overlapping grant transactions gave the principal both halves of a toxic pair (A: %v, B: %v)", errA, errB)
			require.Error(t, errB)
			require.True(t, strings.Contains(errB.Error(), "separation-of-duties"), "replica B is refused by the in-transaction re-check, got: %v", errB)
		})
	}
}

// The group-grant fence: A grants the roles.assign half to the target's group,
// B the secrets.delete half to the target directly; B starts at A's grant write
// (after A's fence row-locked the member) and must wait for A's transaction.
func TestNamedLockOverlap_SoDGroupGrant_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	proj, roleA, roleB, user, _ := seedSoDPG(t, setupDB)
	grp := models.Group{Name: "sod-members"}
	require.NoError(t, setupDB.Create(&grp).Error)
	require.NoError(t, setupDB.Create(&models.UserGroup{UserID: user, GroupID: grp.ID}).Error)
	closePG(setupDB)
	scope := Scope{ProjectID: proj}

	errA, errB, early := overlapPGRun(t, dsn, func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{AssignRoleToGroup: func(next storage.Storage, ctx context.Context, groupID, roleID uint, sc storage.Scope) error {
			start()
			return next.AssignRoleToGroup(ctx, groupID, roleID, sc)
		}}
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.AssignRoleToGroup(ctx, 0, grp.ID, roleA, scope, false)
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.AssignUserRole(ctx, 0, user, roleB, scope, false)
	})

	check := pgOpen(t, dsn)
	defer closePG(check)
	var groupGrants, directGrants int64
	require.NoError(t, check.Model(&models.GroupRole{}).Where("group_id = ? AND role_id = ?", grp.ID, roleA).Count(&groupGrants).Error)
	require.NoError(t, check.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", user, roleB).Count(&directGrants).Error)
	require.NoError(t, errA, "replica A held the member's row first and must win")
	require.False(t, early, "replica B's grant transaction must wait for A's (it finished while A's was open: %v)", errB)
	require.False(t, groupGrants == 1 && directGrants == 1, "two overlapping grant transactions gave the member both halves of a toxic pair (A: %v, B: %v)", errA, errB)
	require.Error(t, errB)
	require.True(t, strings.Contains(errB.Error(), "separation-of-duties"), "replica B is refused by the in-transaction re-check, got: %v", errB)
}
