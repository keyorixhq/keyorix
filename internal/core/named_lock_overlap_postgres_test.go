// named_lock_overlap_postgres_test.go — NAMEDLOCK-OVERLAP-1: the PostgreSQL half
// of named_lock_overlap_last_admin_test.go. That test lets the second holder run
// to completion before the first opens its write transaction; this one opens
// both write transactions at once, on two replicas with their own pools, which is
// what the row-lock fence (fenceLastAdminDeactivationOn) is for: the second
// replica's transaction must wait on the global admin grant rows the first holds,
// then see the first one's commit and refuse.
//
// Replica A's named lock is granted by a fake backend (it never reaches
// PostgreSQL), which is the state after its real advisory lock was lost: replica
// B then takes the real lock at once. B is started from inside A's write
// transaction, after A's fence, while A still holds its row locks.
package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestNamedLockOverlap_SuspendUser_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	require.NoError(t, setupDB.Create(&models.Role{Name: "admin", BypassesPermissionChecks: true}).Error)
	var role models.Role
	require.NoError(t, setupDB.Where("name = ?", "admin").First(&role).Error)
	admin1 := models.User{Username: "ol-1", UsernameFolded: "ol-1", IsActive: true, AccountState: AccountActive}
	admin2 := models.User{Username: "ol-2", UsernameFolded: "ol-2", IsActive: true, AccountState: AccountActive}
	require.NoError(t, setupDB.Create(&admin1).Error)
	require.NoError(t, setupDB.Create(&admin2).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: admin1.ID, RoleID: role.ID}).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: admin2.ID, RoleID: role.ID}).Error)
	closePG(setupDB)

	dbA, dbB := pgOpen(t, dsn), pgOpen(t, dsn)
	replicaB := NewKeyorixCore(localstore.NewLocalStorage(dbB))

	var (
		once      sync.Once
		bDone     = make(chan struct{})
		errB      error
		bFinished bool // B finished while A's write transaction was still open
	)
	startB := func() {
		go func() {
			defer close(bDone)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			errB = replicaB.SuspendUser(ctx, admin1.ID, admin2.ID)
		}()
		select {
		case <-bDone:
			bFinished = true
		case <-time.After(750 * time.Millisecond):
		}
	}
	replicaA := NewKeyorixCore(storagetest.Hooked(localstore.NewLocalStorage(dbA), &storagetest.StoreHooks{
		WrapTx: true,
		// The lost lock: A keeps running its section without holding the key.
		WithNamedLock: func(_ storage.Storage, ctx context.Context, _ string, fn func(context.Context) error) error {
			return fn(ctx)
		},
		// Inside A's write transaction, after the fence and before A's own write.
		LockUserForUpdate: func(next storage.Storage, ctx context.Context, id uint) (*models.User, error) {
			if id == admin1.ID {
				once.Do(startB)
			}
			return next.LockUserForUpdate(ctx, id)
		},
	}))

	errA := replicaA.SuspendUser(context.Background(), admin2.ID, admin1.ID)
	select {
	case <-bDone:
	case <-time.After(30 * time.Second):
		t.Fatal("replica B did not finish")
	}
	closePG(dbA)
	closePG(dbB)

	var u1, u2 models.User
	check := pgOpen(t, dsn)
	require.NoError(t, check.First(&u1, admin1.ID).Error)
	require.NoError(t, check.First(&u2, admin2.ID).Error)
	closePG(check)
	usable := func(u models.User) bool { return u.IsActive && !AccountLoginBlocked(u.ID, u.AccountState) }

	require.NoError(t, errA, "replica A held its row locks first and must win")
	require.False(t, bFinished, "replica B's write transaction must wait for A's (it finished while A's was open: %v)", errB)
	require.True(t, usable(u2),
		"both admins were suspended by two overlapping write transactions: no admin is left (A: %v, B: %v)", errA, errB)
	require.True(t, errors.Is(errB, ErrLastAdminDeactivation), "replica B is refused by the in-transaction re-check, got: %v", errB)
	require.False(t, usable(u1))
}
