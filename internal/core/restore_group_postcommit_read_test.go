package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRestoreGroup_PostCommitGetGroupErrorRollsBackTheRestore is the
// regression test for #2428 (FuzzStorageFaultOperations input decoding, on
// current main, to op="GRPC keyorix.v1.GroupService.RestoreGroup"
// fault=(method=GetGroup, NthCall=1, kind=error)): the gRPC handler used to
// call core.RestoreGroup (commits) then a separate core.GetGroup (can fail),
// reporting a committed restore as an error. RestoreGroup now wraps the
// storage restore and its own read-back in one transaction, so a failure in
// the read-back rolls the restore back too -- "reported failed" and "nothing
// happened" stay in sync.
func TestRestoreGroup_PostCommitGetGroupErrorRollsBackTheRestore(t *testing.T) {
	t.Parallel()
	c, db := newRestoreCeilingCore(t)
	ctx := context.Background()

	g, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: "viewers"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: g.ID, RoleID: 2}).Error)
	require.NoError(t, c.DeleteGroup(ctx, 1, g.ID))

	st := c.storage
	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "GetGroup", NthCall: 1, Kind: faultstorage.KindError,
		Err: assert.AnError,
	})

	restored, err := c.RestoreGroup(ctx, 1, g.ID)
	require.Error(t, err, "a failed read-back must be reported as an error")
	assert.Nil(t, restored)

	// Confirm via a fresh, unfaulted read: the group is STILL soft-deleted --
	// the transaction genuinely rolled back the restore too, it did not
	// half-apply (restore committed while the caller was told it failed).
	c.storage = st
	_, getErr := c.GetGroup(ctx, g.ID)
	assert.Error(t, getErr, "a rolled-back restore must leave the group soft-deleted")
}

// TestRestoreGroup_PostCommitGetGroupErrorRollsBackTheRestore_Postgres is the
// real-Postgres sibling: the rollback this fix relies on is a nested
// WithTransaction (SAVEPOINT) inside RestoreGroup, and SQLite's transaction
// semantics are not always a faithful proxy for Postgres's. Skips when
// KEYORIX_TEST_PG_DSN is unset.
func TestRestoreGroup_PostCommitGetGroupErrorRollsBackTheRestore_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgIsolatedSchemaDSN(t, base))
	require.NoError(t, kxstorage.MigrateExisting(db))
	st := store.NewLocalStorage(db)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "pgrestoreadmin", NameFolded: "pgrestoreadmin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "pgrestoreviewer", NameFolded: "pgrestoreviewer"}).Error)
	require.NoError(t, db.Create(&models.User{Username: "pgrestorenonadmin", UsernameFolded: "pgrestorenonadmin", Email: "pgrestorenonadmin@example.com", EmailFolded: "pgrestorenonadmin@example.com", IsActive: true}).Error)

	g, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: "pg-viewers"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: g.ID, RoleID: 2}).Error)
	require.NoError(t, c.DeleteGroup(ctx, 1, g.ID))

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "GetGroup", NthCall: 1, Kind: faultstorage.KindError,
		Err: assert.AnError,
	})

	restored, err := c.RestoreGroup(ctx, 1, g.ID)
	require.Error(t, err)
	assert.Nil(t, restored)

	c.storage = st
	_, getErr := c.GetGroup(ctx, g.ID)
	assert.Error(t, getErr, "a rolled-back restore must leave the group soft-deleted (Postgres)")
}
