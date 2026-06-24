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

func newPurgeTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Project{}, &models.Environment{}))
	return NewLocalStorage(db)
}

func TestPurgeDeletedUsersBefore(t *testing.T) {
	ls := newPurgeTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// Three users: live, soft-deleted long ago, soft-deleted recently.
	require.NoError(t, ls.db.Create(&models.User{ID: 1, Username: "live", Email: "l@x"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 2, Username: "old", Email: "o@x"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 3, Username: "recent", Email: "r@x"}).Error)
	// Soft-delete 2 (40 days ago) and 3 (1 day ago) by stamping deleted_at directly.
	require.NoError(t, ls.db.Unscoped().Model(&models.User{}).Where("id = ?", 2).Update("deleted_at", now.AddDate(0, 0, -40)).Error)
	require.NoError(t, ls.db.Unscoped().Model(&models.User{}).Where("id = ?", 3).Update("deleted_at", now.AddDate(0, 0, -1)).Error)

	cutoff := now.AddDate(0, 0, -30) // 30-day retention
	n, err := ls.PurgeDeletedUsersBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "only the 40-day-old soft-deleted user is purged")

	// The purged user is gone even with Unscoped; live + recent remain.
	var count int64
	require.NoError(t, ls.db.Unscoped().Model(&models.User{}).Count(&count).Error)
	assert.Equal(t, int64(2), count)

	var purged int64
	require.NoError(t, ls.db.Unscoped().Model(&models.User{}).Where("id = ?", 2).Count(&purged).Error)
	assert.Equal(t, int64(0), purged, "row hard-deleted")
}

func TestPurgeDeletedProjectsAndEnvironments(t *testing.T) {
	ls := newPurgeTestStore(t)
	ctx := context.Background()
	old := time.Now().AddDate(0, 0, -40)
	cutoff := time.Now().AddDate(0, 0, -30)

	require.NoError(t, ls.db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, ls.db.Unscoped().Model(&models.Project{}).Where("id = ?", 1).Update("deleted_at", old).Error)
	require.NoError(t, ls.db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	require.NoError(t, ls.db.Unscoped().Model(&models.Environment{}).Where("id = ?", 1).Update("deleted_at", old).Error)

	np, err := ls.PurgeDeletedProjectsBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), np)

	ne, err := ls.PurgeDeletedEnvironmentsBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), ne)
}

func TestPurgeDeletedUsersBefore_NothingToPurge(t *testing.T) {
	ls := newPurgeTestStore(t)
	require.NoError(t, ls.db.Create(&models.User{ID: 1, Username: "live", Email: "l@x"}).Error)
	n, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "a live (non-deleted) user is never purged")
}

// Purging a soft-deleted secret must also destroy its version rows, which hold the
// encrypted value. Before the fix only the secret_nodes row was deleted, leaving the
// ciphertext recoverable in secret_versions forever — defeating the retention purge's
// irreversibility / GDPR-erasure guarantee.
func TestPurgeDeletedSecretsBefore_DestroysVersions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.SecretDependency{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()
	now := time.Now()

	// One secret soft-deleted 40 days ago, with two ciphertext-bearing versions; and a
	// live secret with a version that must survive.
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "old"}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{ID: 10, SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("ciphertext-1")}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{ID: 11, SecretNodeID: 1, VersionNumber: 2, EncryptedValue: []byte("ciphertext-2")}).Error)
	require.NoError(t, db.Unscoped().Model(&models.SecretNode{}).Where("id = ?", 1).Update("deleted_at", now.AddDate(0, 0, -40)).Error)

	require.NoError(t, db.Create(&models.SecretNode{ID: 2, Name: "live"}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{ID: 20, SecretNodeID: 2, VersionNumber: 1, EncryptedValue: []byte("keep-me")}).Error)

	n, err := ls.PurgeDeletedSecretsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "the 40-day-old soft-deleted secret is purged")

	// Its node and BOTH versions (the ciphertext) are gone, even Unscoped.
	var nodeCount, goneVersions int64
	require.NoError(t, db.Unscoped().Model(&models.SecretNode{}).Where("id = ?", 1).Count(&nodeCount).Error)
	assert.Equal(t, int64(0), nodeCount)
	require.NoError(t, db.Unscoped().Model(&models.SecretVersion{}).Where("secret_node_id = ?", 1).Count(&goneVersions).Error)
	assert.Equal(t, int64(0), goneVersions, "the ciphertext-bearing versions must be destroyed with the secret")

	// The live secret's version is untouched.
	var liveVersions int64
	require.NoError(t, db.Model(&models.SecretVersion{}).Where("secret_node_id = ?", 2).Count(&liveVersions).Error)
	assert.Equal(t, int64(1), liveVersions)
}
