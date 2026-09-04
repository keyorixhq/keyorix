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

func newRoleExpiryStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.UserRole{}))
	return NewLocalStorage(db)
}

func TestListExpiringUserRoles(t *testing.T) {
	ls := newRoleExpiryStore(t)
	db := ls.DB()

	cutoff := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	past := cutoff.Add(-48 * time.Hour) // already expired -- must still be included
	soon := cutoff.Add(-time.Hour)      // expiring before cutoff -- included
	later := cutoff.Add(time.Hour)      // expires after cutoff -- excluded
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ExpiresAt: &past}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ExpiresAt: &soon}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 1, ExpiresAt: &later}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 4, RoleID: 1}).Error) // permanent, ExpiresAt nil -- excluded

	grants, err := ls.ListExpiringUserRoles(context.Background(), cutoff)
	require.NoError(t, err)
	require.Len(t, grants, 2)
	gotUsers := map[uint]bool{}
	for _, g := range grants {
		gotUsers[g.UserID] = true
	}
	assert.True(t, gotUsers[1], "already-expired grants must be included")
	assert.True(t, gotUsers[2])
	assert.False(t, gotUsers[3], "a grant expiring after the cutoff must be excluded")
	assert.False(t, gotUsers[4], "a permanent grant (no ExpiresAt) must be excluded")
}

func TestListExpiringUserRoles_NoneMatch(t *testing.T) {
	ls := newRoleExpiryStore(t)
	grants, err := ls.ListExpiringUserRoles(context.Background(), time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Empty(t, grants)
}
