package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// An EXPIRED (but not-yet-swept) time-bound grant must NOT appear as a project member —
// otherwise a lapsed break-glass admin keeps receiving approver notifications after authz
// has already cut off their access. Live and never-expiring grants still appear.
func TestListProjectMembers_ExcludesExpiredGrants(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	const proj = uint(2)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice"}).Error) // permanent admin
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob"}).Error)   // live break-glass
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "carol"}).Error) // EXPIRED break-glass
	require.NoError(t, db.Create(&models.Role{ID: 9, Name: "project_admin"}).Error)

	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 9, ProjectID: proj}).Error)                     // no expiry
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 9, ProjectID: proj, ExpiresAt: &future}).Error) // live
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 9, ProjectID: proj, ExpiresAt: &past}).Error)   // expired

	members, err := ls.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	got := map[string]bool{}
	for _, m := range members {
		got[m.Username] = true
	}
	assert.True(t, got["alice"], "a permanent grant is a member")
	assert.True(t, got["bob"], "a live time-bound grant is a member")
	assert.False(t, got["carol"], "an expired (unswept) grant must NOT be a member")
}
