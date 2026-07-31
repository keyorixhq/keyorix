package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newQuotaStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	return NewLocalStorage(db)
}

func intPtr(n int) *int { return &n }

func TestListSecretsWithQuota_ReturnsSecretsWithMaxReads(t *testing.T) {
	s := newQuotaStore(t)
	ctx := context.Background()

	// Secret with MaxReads set — should be returned.
	withQuota := models.SecretNode{
		Name:      "quota-secret",
		IsSecret:  true,
		MaxReads:  intPtr(10),
		ReadCount: 3,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, s.db.Create(&withQuota).Error)

	// Secret without MaxReads — must be excluded.
	noQuota := models.SecretNode{
		Name:      "no-quota",
		IsSecret:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, s.db.Create(&noQuota).Error)

	// Folder node (IsSecret=false) with MaxReads — must be excluded.
	folder := models.SecretNode{
		Name:      "a-folder",
		IsSecret:  false,
		MaxReads:  intPtr(5),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, s.db.Create(&folder).Error)

	rows, err := s.ListSecretsWithQuota(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, withQuota.ID, rows[0].ID)
}

func TestListSecretsWithQuota_ExcludesSoftDeleted(t *testing.T) {
	s := newQuotaStore(t)
	ctx := context.Background()

	// Soft-deleted secret with MaxReads — must be excluded.
	deleted := models.SecretNode{
		Name:      "deleted-quota",
		IsSecret:  true,
		MaxReads:  intPtr(5),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, s.db.Create(&deleted).Error)
	// Soft-delete it.
	require.NoError(t, s.db.Delete(&deleted).Error)

	rows, err := s.ListSecretsWithQuota(ctx)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListSecretsWithQuota_ExcludesZeroMaxReads(t *testing.T) {
	s := newQuotaStore(t)
	ctx := context.Background()

	// A secret with MaxReads explicitly set to 0 should be excluded.
	zeroMax := models.SecretNode{
		Name:      "zero-max",
		IsSecret:  true,
		MaxReads:  intPtr(0),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, s.db.Create(&zeroMax).Error)

	rows, err := s.ListSecretsWithQuota(ctx)
	require.NoError(t, err)
	assert.Empty(t, rows)
}
