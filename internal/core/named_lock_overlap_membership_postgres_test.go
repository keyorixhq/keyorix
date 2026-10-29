// named_lock_overlap_membership_postgres_test.go — NAMEDLOCK-OVERLAP-2, the
// PostgreSQL half of named_lock_overlap_membership_test.go: replica B's revoke
// starts while replica A's activation grant transaction is open (after A's
// fence re-read the membership as active). B's state CAS must wait for A's
// transaction (both take membershipLockKey with LockNamedKeyInTx), so B's
// removal then sees A's grant and removes it: no grant on a revoked membership.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestNamedLockOverlap_MembershipActivation_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	require.NoError(t, setupDB.AutoMigrate(&models.ProjectMembership{}, &models.SoDPolicy{}, &models.Notification{}))
	proj := models.Project{Name: "membership-overlap"}
	require.NoError(t, setupDB.Create(&proj).Error)
	admin := models.Role{Name: "admin", BypassesPermissionChecks: true}
	dev := models.Role{Name: "project_developer"}
	require.NoError(t, setupDB.Create(&admin).Error)
	require.NoError(t, setupDB.Create(&dev).Error)
	actor := models.User{Username: "m-actor", UsernameFolded: "m-actor", IsActive: true, AccountState: AccountActive}
	member := models.User{Username: "m-member", UsernameFolded: "m-member", IsActive: true, AccountState: AccountActive}
	require.NoError(t, setupDB.Create(&actor).Error)
	require.NoError(t, setupDB.Create(&member).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: actor.ID, RoleID: admin.ID}).Error)
	ms := models.ProjectMembership{ProjectID: proj.ID, UserID: member.ID, Role: dev.Name, State: MembershipProvisioned}
	require.NoError(t, setupDB.Create(&ms).Error)
	closePG(setupDB)

	errA, errB, early := overlapPGRun(t, dsn, func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{AssignRole: func(next storage.Storage, ctx context.Context, userID, roleID uint, sc storage.Scope) error {
			start() // inside A's grant transaction, after its fence
			return next.AssignRole(ctx, userID, roleID, sc)
		}}
	}, func(ctx context.Context, c *KeyorixCore) error {
		_, err := c.TransitionMembership(ctx, proj.ID, ms.ID, MembershipActive, actor.ID, false)
		return err
	}, func(ctx context.Context, c *KeyorixCore) error {
		_, err := c.TransitionMembership(ctx, proj.ID, ms.ID, MembershipRevoked, actor.ID, false)
		return err
	})

	check := pgOpen(t, dsn)
	defer closePG(check)
	var got models.ProjectMembership
	require.NoError(t, check.First(&got, ms.ID).Error)
	var grants int64
	require.NoError(t, check.Model(&models.UserRole{}).Where("user_id = ? AND project_id = ?", member.ID, proj.ID).Count(&grants).Error)
	require.NoError(t, errA, "replica A's activation held the membership key first and must commit")
	require.False(t, early, "replica B's revoke must wait for A's grant transaction (it finished while A's was open: %v)", errB)
	require.NoError(t, errB, "replica B's revoke runs after A's commit and must succeed")
	require.Equal(t, MembershipRevoked, got.State)
	require.Zero(t, grants, "a revoked membership kept its role grant: B's removal ran before A's grant committed (A: %v, B: %v)", errA, errB)
}
