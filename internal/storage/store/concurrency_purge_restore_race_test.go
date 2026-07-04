// concurrency_purge_restore_race_test.go — regression coverage for #276: a concurrent
// RestoreSecret landing in the window between PurgeDeletedSecretsBefore's SELECT (Pluck)
// and its DELETE must not be silently undone by the purge.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestConcurrency_PurgeDeletedSecretsBefore_RestoreWinsRace drives the #276 exploit
// trace deterministically: a gorm callback fires immediately after
// PurgeDeletedSecretsBefore's transaction has Plucked the stale-eligible IDs but before
// it deletes the first dependent row (secret_versions), and — right there, on the SAME
// transaction handle — flips the target secret's deleted_at back to NULL, exactly as a
// concurrent RestoreSecret commit would have left it in that window. (A genuinely
// separate goroutine + connection racing a real RestoreSecret call was tried first, but
// deadlocks under plain rollback-journal SQLite: the purge's own initial Pluck already
// holds a SHARED lock for the rest of the transaction, which blocks a second connection's
// UPDATE from ever acquiring the write lock it needs — the two only ever resolve via
// _busy_timeout expiring. Mutating deleted_at on the same transaction reproduces the
// exact "stale ids list, live row changed since" condition the fix's delete-time
// re-check protects against, without that lock-ordering artifact.)
//
// Before the fix, the purge deleted purely off the stale ID list and hard-deleted the
// secret (and its version) anyway, silently undoing a restore that had already reported
// success. After the fix, every delete re-checks deleted_at at delete time, so the
// now-live secret and its version row must both survive.
func TestConcurrency_PurgeDeletedSecretsBefore_RestoreWinsRace(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretDependency{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	sec := &models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "race-me", IsSecret: true}
	require.NoError(t, db.Create(sec).Error)
	require.NoError(t, db.Create(&models.SecretVersion{ID: 10, SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("ciphertext")}).Error)
	// Soft-deleted 40 days ago — squarely past a 30-day retention cutoff, so the purge's
	// Pluck picks it up as eligible before anyone restores it.
	require.NoError(t, db.Unscoped().Model(&models.SecretNode{}).Where("id = ?", 1).
		Update("deleted_at", time.Now().AddDate(0, 0, -40)).Error)

	var fired bool
	db.Callback().Delete().Before("gorm:delete").Register(
		"test:simulate-concurrent-restore-before-secret-version-delete",
		func(tx *gorm.DB) {
			if fired {
				return
			}
			if _, ok := tx.Statement.Dest.(*models.SecretVersion); !ok {
				return
			}
			fired = true
			// Simulate a concurrent RestoreSecret landing in the window between the
			// purge's Pluck (already ran) and this delete — raw SQL on tx's own
			// *sql.Tx (via Exec, not a cloned Statement/Session builder, which fights
			// the in-progress "gorm:delete" statement's own Model/Table/Where state)
			// so this participates in the still-open purge transaction rather than
			// needing a second connection, which either deadlocks under SQLite's
			// locking model (see the doc comment above) or, for ":memory:", wouldn't
			// even see the same database at all.
			require.NoError(t, tx.Exec("UPDATE secret_nodes SET deleted_at = NULL WHERE id = ?", 1).Error)
		},
	)

	purgedCount, purgeErr := ls.PurgeDeletedSecretsBefore(ctx, time.Now().AddDate(0, 0, -30))
	require.NoError(t, purgeErr)
	assert.True(t, fired, "the callback must have fired — otherwise this test isn't exercising the race window at all")
	assert.Equal(t, int64(0), purgedCount, "the concurrently-restored secret must be excluded from the purge count")

	// The secret must be alive — not hard-deleted despite having been in the stale ID list.
	var node models.SecretNode
	require.NoError(t, db.First(&node, sec.ID).Error, "a scoped read must find the restored secret live")
	assert.False(t, node.DeletedAt.Valid, "must be live (deleted_at cleared), not soft-deleted")

	// Its version (the ciphertext) must survive too.
	var version models.SecretVersion
	require.NoError(t, db.First(&version, 10).Error, "the version row must survive — the purge must not have destroyed it")
}
