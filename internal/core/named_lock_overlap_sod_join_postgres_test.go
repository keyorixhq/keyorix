// named_lock_overlap_sod_join_postgres_test.go — NAMEDLOCK-FENCE-1, the
// PostgreSQL half of named_lock_overlap_sod_join_test.go: a group join and a
// grant to that group, both write transactions open at once on two replicas
// (overlapPGRun). Replica B starts inside A's transaction, after A's fence and
// before A's write. Both transactions take the group's key with
// LockNamedKeyInTx, so B must wait for A, then see A's committed write (the
// join's membership, or the grant) and be refused.
//
// Before NAMEDLOCK-FENCE-1 both orders committed a toxic pair: the join's
// transaction took only the user's row, the grant's only its listed members'
// rows, and neither could see the other's uncommitted write.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestNamedLockOverlap_SoDGroupJoinVsGroupGrant_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	// B starts at A's membership write, after A's fence.
	hookJoin := func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{AddUserToGroup: func(next storage.Storage, ctx context.Context, userID, groupID, projectID uint) error {
			start()
			return next.AddUserToGroup(ctx, userID, groupID, projectID)
		}}
	}
	// B starts at A's group grant write, after A's fence.
	hookGrant := func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{AssignRoleToGroup: func(next storage.Storage, ctx context.Context, groupID, roleID uint, sc storage.Scope) error {
			start()
			return next.AssignRoleToGroup(ctx, groupID, roleID, sc)
		}}
	}
	type ids struct{ actor, user, group, role, proj uint }
	join := func(ctx context.Context, c *KeyorixCore, x ids) error {
		return c.AddUserToGroup(ctx, x.actor, false, x.user, x.group, 0)
	}
	grant := func(ctx context.Context, c *KeyorixCore, x ids) error {
		return c.AssignRoleToGroup(ctx, x.actor, x.group, x.role, Scope{ProjectID: x.proj}, false)
	}
	cases := []struct {
		name   string
		hookAt func(start func()) *storagetest.StoreHooks
		a, b   func(ctx context.Context, c *KeyorixCore, x ids) error
	}{
		{"join then grant", hookJoin, join, grant},
		{"grant then join", hookGrant, grant, join},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dsn, setupDB := newPGLastAdminSchemaDSN(t)
			proj, roleA, roleB, user, _ := seedSoDPG(t, setupDB)
			admin := models.Role{Name: "sod-join-admin", BypassesPermissionChecks: true}
			require.NoError(t, setupDB.Create(&admin).Error)
			actor := models.User{Username: "sod-join-actor", UsernameFolded: "sod-join-actor", IsActive: true, AccountState: AccountActive}
			require.NoError(t, setupDB.Create(&actor).Error)
			require.NoError(t, setupDB.Create(&models.UserRole{UserID: actor.ID, RoleID: admin.ID}).Error)
			require.NoError(t, setupDB.Create(&models.UserRole{UserID: user, RoleID: roleB, ProjectID: proj}).Error)
			grp := models.Group{Name: "sod-join-empty"}
			require.NoError(t, setupDB.Create(&grp).Error)
			closePG(setupDB)
			x := ids{actor: actor.ID, user: user, group: grp.ID, role: roleA, proj: proj}

			errA, errB, early := overlapPGRun(t, dsn, tc.hookAt, func(ctx context.Context, c *KeyorixCore) error {
				return tc.a(ctx, c, x)
			}, func(ctx context.Context, c *KeyorixCore) error {
				return tc.b(ctx, c, x)
			})

			check := pgOpen(t, dsn)
			defer closePG(check)
			var joined, granted int64
			require.NoError(t, check.Model(&models.UserGroup{}).Where("user_id = ? AND group_id = ?", user, grp.ID).Count(&joined).Error)
			require.NoError(t, check.Model(&models.GroupRole{}).Where("group_id = ? AND role_id = ?", grp.ID, roleA).Count(&granted).Error)
			require.NoError(t, errA, "replica A held the group key first and must win")
			require.False(t, early, "replica B's transaction must wait for A's (it finished while A's was open: %v)", errB)
			require.False(t, joined == 1 && granted == 1, "an overlapping join and group grant gave the user both halves of a toxic pair (A: %v, B: %v)", errA, errB)
			require.Error(t, errB)
			require.True(t, strings.Contains(errB.Error(), "separation-of-duties"), "replica B is refused by the in-transaction re-check, got: %v", errB)
		})
	}
}
