// local_secrets_retention_override_test.go — SQLite integration test for
// LocalStorage.SetRetentionOverride.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newSetRetentionOverrideStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	return NewLocalStorage(db)
}

// TestSetRetentionOverride_SetsField verifies that SetRetentionOverride persists
// the override to the SecretNode row and that a subsequent read returns the new value.
func TestSetRetentionOverride_SetsField(t *testing.T) {
	ls := newSetRetentionOverrideStore(t)
	ctx := context.Background()

	node := &models.SecretNode{ID: 1, Name: "high-value", IsSecret: true}
	require.NoError(t, ls.db.Create(node).Error)

	require.NoError(t, ls.SetRetentionOverride(ctx, 1, 90))

	var got models.SecretNode
	require.NoError(t, ls.db.First(&got, 1).Error)
	assert.Equal(t, 90, got.RetentionOverrideDays)
}

// TestSetRetentionOverride_ClearsField verifies that passing days=0 clears a
// previously-set override (reverts to global policy).
func TestSetRetentionOverride_ClearsField(t *testing.T) {
	ls := newSetRetentionOverrideStore(t)
	ctx := context.Background()

	node := &models.SecretNode{ID: 2, Name: "s2", IsSecret: true, RetentionOverrideDays: 60}
	require.NoError(t, ls.db.Create(node).Error)

	require.NoError(t, ls.SetRetentionOverride(ctx, 2, 0))

	var got models.SecretNode
	require.NoError(t, ls.db.First(&got, 2).Error)
	assert.Equal(t, 0, got.RetentionOverrideDays)
}

// TestSetRetentionOverride_ClosedDB_ReturnsError verifies the error branch:
// when the underlying SQLite connection is closed, SetRetentionOverride must
// propagate the storage error rather than silently returning nil.
func TestSetRetentionOverride_ClosedDB_ReturnsError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	ls := NewLocalStorage(db)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	err = ls.SetRetentionOverride(context.Background(), 1, 30)
	assert.Error(t, err)
}
