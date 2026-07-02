package store

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// secretVersionConcurrentDB opens a temp FILE-backed SQLite (not :memory:) with a busy
// timeout and WAL, so multiple connections genuinely contend — the only way to exercise
// CreateNextSecretVersion's optimistic-retry-under-a-unique-index design under real
// concurrency. It also creates the (secret_node_id, version_number) unique index that
// ensureSecretVersionIndex (internal/storage/factory.go) installs in production — without
// it, CreateNextSecretVersion's retry loop has nothing to actually catch a losing writer on.
func secretVersionConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "sv.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretVersion{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_secret_versions_node_version ON secret_versions (secret_node_id, version_number)").Error)
	return db
}

// TestConcurrency_CreateNextSecretVersion_NeverDuplicates is the #121 regression: a manual
// rotation racing scheduled auto-rotation (or two concurrent updates) on the SAME secret
// used to both read the same MAX(version_number) and both insert "next", producing a
// duplicate version number — a lost update, since GetLatest then resolves to one of the two
// non-deterministically and the other silently vanishes from the version history. This
// drives many concurrent writers at CreateNextSecretVersion for one secret and asserts every
// resulting version number is unique and the full 1..N run is present with no gaps.
func TestConcurrency_CreateNextSecretVersion_NeverDuplicates(t *testing.T) {
	db := secretVersionConcurrentDB(t)
	ls := NewLocalStorage(db)

	const secretNodeID = uint(1)
	const writers = 30

	var succeeded atomic.Int64
	errs := make(chan error, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			_, err := ls.CreateNextSecretVersion(context.Background(), &models.SecretVersion{
				SecretNodeID:   secretNodeID,
				EncryptedValue: []byte("value"),
			})
			if err != nil {
				errs <- err
				return
			}
			succeeded.Add(1)
		}(i)
	}
	close(start) // release all writers at once
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "every writer must eventually succeed via retry, not error out")
	}
	assert.Equal(t, int64(writers), succeeded.Load())

	var rows []models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", secretNodeID).Order("version_number ASC").Find(&rows).Error)
	require.Len(t, rows, writers, "exactly one row per successful writer, no lost updates")

	seen := make(map[int]bool, writers)
	for _, r := range rows {
		assert.False(t, seen[r.VersionNumber], "duplicate version_number %d means two writers raced past the unique index", r.VersionNumber)
		seen[r.VersionNumber] = true
	}
	for n := 1; n <= writers; n++ {
		assert.True(t, seen[n], "version_number %d is missing — the 1..N run must be gap-free", n)
	}
}
