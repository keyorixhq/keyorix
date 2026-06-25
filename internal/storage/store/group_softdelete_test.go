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

// TestGroupShare_SoftDeletedMemberExcluded pins that a soft-deleted user no longer
// inherits group shares and no longer appears as a group member.
func TestGroupShare_SoftDeletedMemberExcluded(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Group{}, &models.UserGroup{},
		&models.ShareRecord{}, &models.SecretNode{},
	))
	ls := NewLocalStorage(db)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alive", Email: "a@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "gone", Email: "g@x.io"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "team"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 100, Name: "s", ProjectID: 1, EnvironmentID: 1, OwnerID: 9, Status: "active", Type: "password",
	}).Error)
	// Share the secret with the group.
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: 100, RecipientID: 10, IsGroup: true, Permission: "read",
	}).Error)

	// Both members see the group share and have permission.
	for _, uid := range []uint{1, 2} {
		secrets, lerr := ls.ListSharedSecrets(ctx, uid)
		require.NoError(t, lerr)
		assert.Len(t, secrets, 1, "user %d should see the group share", uid)
		perm, perr := ls.CheckSharePermission(ctx, 100, uid)
		require.NoError(t, perr)
		assert.Equal(t, "read", perm, "user %d permission", uid)
	}
	members, merr := ls.ListGroupMembers(ctx, 10)
	require.NoError(t, merr)
	assert.Len(t, members, 2)

	// Soft-delete user 2.
	require.NoError(t, db.Delete(&models.User{}, 2).Error)

	// User 2 no longer inherits the group share, has no permission, and is not listed.
	secrets, lerr := ls.ListSharedSecrets(ctx, 2)
	require.NoError(t, lerr)
	assert.Empty(t, secrets, "a soft-deleted user must not inherit group shares")
	perm, perr := ls.CheckSharePermission(ctx, 100, 2)
	require.Error(t, perr, "a soft-deleted user must have no group-share permission")
	assert.Equal(t, "", perm)
	members, merr = ls.ListGroupMembers(ctx, 10)
	require.NoError(t, merr)
	require.Len(t, members, 1, "a soft-deleted user must not appear in the member list")
	assert.Equal(t, uint(1), members[0].ID)

	// The live member is unaffected.
	secrets, lerr = ls.ListSharedSecrets(ctx, 1)
	require.NoError(t, lerr)
	assert.Len(t, secrets, 1)
}
