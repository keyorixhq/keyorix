package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// sharingConcurrentDB opens a temp FILE-backed SQLite (not :memory:) with a busy
// timeout and WAL, so multiple connections genuinely contend — the only way to test
// that the create-race fix holds under real concurrency (mirrors concurrentDB in
// concurrency_max_reads_test.go). It also installs the same partial unique index the
// real migration does (ensureShareRecordUniqueIndex, internal/storage/factory.go —
// not importable here without a cycle, so the DDL is mirrored).
func sharingConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "sharing.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Group{}, &models.UserGroup{}, &models.SecretNode{}, &models.ShareRecord{},
	))
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_share_records_active ON share_records (secret_id, recipient_id, is_group) WHERE deleted_at IS NULL",
	).Error)
	return db
}

// #136: two concurrent CreateShareRecord calls for the same (secret, recipient) must
// not both succeed as separate rows — the partial unique index rejects the loser's
// INSERT, and CreateShareRecord must turn that into an upsert onto the winner's row
// rather than surfacing a raw constraint error to the caller.
func TestCreateShareRecord_ConcurrentGrantsNoDuplicateRow(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee", Email: "g@x.io"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{
				SecretID: 100, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read",
			})
			errs[i] = err
		}(i)
	}
	start.Done() // release all goroutines at once to maximize the race window
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d", i)
	}

	var count int64
	require.NoError(t, db.Model(&models.ShareRecord{}).
		Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL", 100, 2, false).
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "concurrent grants for the same (secret, recipient) must collapse to exactly one active row")
}

// #136: DeleteShareRecord must remove every active row for the target's
// (secret, recipient, is_group), not just the row named by shareID — so a
// pre-existing duplicate (e.g. from before the unique index shipped) doesn't survive
// a revoke and leave access live.
func TestDeleteShareRecord_RemovesAllDuplicatesForSameTuple(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "grantee", Email: "g@x.io"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 1, Status: "active", Type: "password",
	}).Error)

	// Simulate a pre-existing duplicate from before the unique index existed: insert
	// directly, bypassing CreateShareRecord (which would now reject/upsert it).
	share1 := &models.ShareRecord{SecretID: 100, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read"}
	require.NoError(t, db.Exec("DROP INDEX IF EXISTS uniq_share_records_active").Error)
	require.NoError(t, db.Create(share1).Error)
	share2 := &models.ShareRecord{SecretID: 100, RecipientID: 2, IsGroup: false, OwnerID: 1, Permission: "read"}
	require.NoError(t, db.Create(share2).Error)

	var preCount int64
	require.NoError(t, db.Model(&models.ShareRecord{}).
		Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL", 100, 2, false).
		Count(&preCount).Error)
	require.Equal(t, int64(2), preCount, "test setup: two duplicate active rows must exist")

	// Revoke by share1's ID only.
	require.NoError(t, ls.DeleteShareRecord(ctx, share1.ID))

	perm, err := ls.CheckSharePermission(ctx, 100, 2)
	require.Error(t, err, "revoking one of the duplicate rows must remove access entirely")
	assert.Equal(t, "", perm)

	var postCount int64
	require.NoError(t, db.Model(&models.ShareRecord{}).
		Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL", 100, 2, false).
		Count(&postCount).Error)
	assert.Equal(t, int64(0), postCount, "both duplicate rows must be removed by a single revoke")
}

// #136: CheckSharePermission's OwnerID==userID check must not match when both are the
// zero value. A machine actor's ID is also 0, so an unguarded equality would grant it
// owner-level "write" on every ownerless (machine-created) secret.
func TestCheckSharePermission_OwnerZeroGuard(t *testing.T) {
	db := sharingConcurrentDB(t)
	ls := NewLocalStorage(db)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 0, Status: "active", Type: "password",
	}).Error)

	perm, err := ls.CheckSharePermission(ctx, 100, 0)
	require.Error(t, err, "userID=0 must not match an ownerless secret's OwnerID=0")
	assert.Equal(t, "", perm)
}
