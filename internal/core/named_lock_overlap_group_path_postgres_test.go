// named_lock_overlap_group_path_postgres_test.go — NAMEDLOCK-OVERLAP-2, the
// PostgreSQL half of named_lock_overlap_group_path_test.go: both write
// transactions open at once, on two replicas with their own pools. Replica A's
// named lock is granted by a fake backend (its real advisory lock was lost);
// replica B starts from inside A's write transaction, after A's fence and
// before A's write. B must wait for A's transaction (grant rows FOR UPDATE at
// the global scope, the project's LockNamedKeyInTx key at project scope), then
// see A's commit and be refused.
package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// overlapPGRun runs opA on a replica whose named locks are granted without
// PostgreSQL (lost), and starts opB on a real replica when A's write
// transaction reaches the storage call hooks names (through hookAt). It returns
// both errors and whether B finished while A's transaction was still open.
func overlapPGRun(t *testing.T, dsn string, hookAt func(start func()) *storagetest.StoreHooks,
	opA func(ctx context.Context, c *KeyorixCore) error, opB func(ctx context.Context, c *KeyorixCore) error,
) (errA, errB error, bFinishedEarly bool) {
	t.Helper()
	dbA, dbB := pgOpen(t, dsn), pgOpen(t, dsn)
	defer closePG(dbA)
	defer closePG(dbB)
	replicaB := NewKeyorixCore(localstore.NewLocalStorage(dbB))
	var once sync.Once
	bDone := make(chan struct{})
	startB := func() {
		go func() {
			defer close(bDone)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			errB = opB(ctx, replicaB)
		}()
		select {
		case <-bDone:
			bFinishedEarly = true
		case <-time.After(750 * time.Millisecond):
		}
	}
	hooks := hookAt(func() { once.Do(startB) })
	hooks.WrapTx = true
	hooks.WithNamedLock = func(_ storage.Storage, ctx context.Context, _ string, fn func(context.Context) error) error {
		return fn(ctx) // the lost lock: A keeps running its section without holding the key
	}
	replicaA := NewKeyorixCore(storagetest.Hooked(localstore.NewLocalStorage(dbA), hooks))
	errA = opA(context.Background(), replicaA)
	select {
	case <-bDone:
	case <-time.After(30 * time.Second):
		t.Fatal("replica B did not finish")
	}
	return errA, errB, bFinishedEarly
}

// seedTwoAdminGroupsPG: groups g1, g2 each hold role at projectID with one
// member each (u1, u2); returns their IDs.
func seedTwoAdminGroupsPG(t *testing.T, db *gorm.DB, projectID uint) (role uint, u, g [2]uint) {
	t.Helper()
	r := models.Role{Name: "admin", BypassesPermissionChecks: true}
	if projectID != 0 {
		r = models.Role{Name: "proj_admin"}
	}
	require.NoError(t, db.Create(&r).Error)
	if projectID != 0 {
		var perm models.Permission
		require.NoError(t, db.Where("name = ?", "roles.assign").First(&perm).Error)
		require.NoError(t, db.Create(&models.RolePermission{RoleID: r.ID, PermissionID: perm.ID}).Error)
	}
	for i, name := range []string{"ga", "gb"} {
		usr := models.User{Username: name, UsernameFolded: name, IsActive: true, AccountState: AccountActive}
		require.NoError(t, db.Create(&usr).Error)
		grp := models.Group{Name: name}
		require.NoError(t, db.Create(&grp).Error)
		require.NoError(t, db.Create(&models.GroupRole{GroupID: grp.ID, RoleID: r.ID, ProjectID: projectID}).Error)
		require.NoError(t, db.Create(&models.UserGroup{UserID: usr.ID, GroupID: grp.ID}).Error)
		u[i], g[i] = usr.ID, grp.ID
	}
	return r.ID, u, g
}

func TestNamedLockOverlap_RemoveUserFromGroup_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	_, u, g := seedTwoAdminGroupsPG(t, setupDB, 0)
	closePG(setupDB)

	errA, errB, early := overlapPGRun(t, dsn, func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{
			RemoveUserFromGroup: func(next storage.Storage, ctx context.Context, userID, groupID, projectID uint) error {
				start()
				return next.RemoveUserFromGroup(ctx, userID, groupID, projectID)
			},
		}
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.RemoveUserFromGroup(ctx, 99, u[0], g[0], 0)
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.RemoveUserFromGroup(ctx, 99, u[1], g[1], 0)
	})

	check := pgOpen(t, dsn)
	defer closePG(check)
	var left int64
	require.NoError(t, check.Model(&models.UserGroup{}).Where("user_id IN ?", []uint{u[0], u[1]}).Count(&left).Error)
	require.NoError(t, errA, "replica A held the grant rows first and must win")
	require.False(t, early, "replica B's write transaction must wait for A's (it finished while A's was open: %v)", errB)
	require.Equal(t, int64(1), left, "both admin memberships were removed by two overlapping transactions: no admin is left (A: %v, B: %v)", errA, errB)
	require.ErrorIs(t, errB, storage.ErrWouldStrandLastAdmin, "replica B is refused by the in-transaction re-check")
}

func TestNamedLockOverlap_RemoveRoleFromGroupProject_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	proj := models.Project{Name: "overlap-proj"}
	require.NoError(t, setupDB.Create(&proj).Error)
	role, _, g := seedTwoAdminGroupsPG(t, setupDB, proj.ID)
	closePG(setupDB)
	scope := Scope{ProjectID: proj.ID}

	errA, errB, early := overlapPGRun(t, dsn, func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{
			RemoveRoleFromGroup: func(next storage.Storage, ctx context.Context, groupID, roleID uint, sc storage.Scope) error {
				start()
				return next.RemoveRoleFromGroup(ctx, groupID, roleID, sc)
			},
		}
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.RemoveRoleFromGroup(ctx, 99, g[0], role, scope)
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.RemoveRoleFromGroup(ctx, 99, g[1], role, scope)
	})

	check := pgOpen(t, dsn)
	defer closePG(check)
	var left int64
	require.NoError(t, check.Model(&models.GroupRole{}).Where("role_id = ? AND project_id = ?", role, proj.ID).Count(&left).Error)
	require.NoError(t, errA, "replica A held the project's transaction key first and must win")
	require.False(t, early, "replica B's write transaction must wait for A's (it finished while A's was open: %v)", errB)
	require.Equal(t, int64(1), left, "both project admin grants were removed by two overlapping transactions (A: %v, B: %v)", errA, errB)
	require.ErrorIs(t, errB, ErrLastAdminGroupGuard, "replica B is refused by the in-transaction re-check")
}
