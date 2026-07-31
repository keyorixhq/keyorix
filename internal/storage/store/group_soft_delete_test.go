package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newGroupSoftDeleteStore(t *testing.T) *LocalStorage {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Role{},
		&models.ShareRecord{}, &models.SecretNode{}, &models.User{},
		&models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "u1", Email: "u1@x.io"}).Error)
	return NewLocalStorage(db)
}

// A soft-deleted group must grant NOTHING — neither inherited roles nor group
// shares — even though its membership/grant/share rows are kept for restore. And
// restoring it brings the access back.
func TestGroupSoftDelete_RevokesThenRestoresAccess(t *testing.T) {
	ls := newGroupSoftDeleteStore(t)
	ctx := context.Background()

	g, err := ls.CreateGroup(ctx, &models.Group{Name: "ops"})
	require.NoError(t, err)
	require.NoError(t, ls.AddUserToGroup(ctx, 1, g.ID, 0))
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: g.ID, RoleID: 50}).Error)
	// A secret shared with the group.
	require.NoError(t, ls.db.Create(&models.SecretNode{ID: 7, Name: "s", IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}).Error)
	require.NoError(t, ls.db.Create(&models.ShareRecord{SecretID: 7, RecipientID: g.ID, IsGroup: true, Permission: "read"}).Error)

	roles := func() []uint {
		ids, e := ls.GetUserGroupRoleIDsAt(ctx, 1, storage.Scope{})
		require.NoError(t, e)
		return ids
	}
	sharedSecretIDs := func() []uint {
		secs, e := ls.ListSharedSecrets(ctx, 1)
		require.NoError(t, e)
		out := make([]uint, 0, len(secs))
		for _, s := range secs {
			out = append(out, s.ID)
		}
		return out
	}

	// Live group: the member inherits the role and sees the shared secret.
	assert.Equal(t, []uint{50}, roles())
	assert.Contains(t, sharedSecretIDs(), uint(7))

	// Soft-delete the group → it authorizes nothing.
	require.NoError(t, ls.DeleteGroup(ctx, g.ID))
	_, err = ls.GetGroup(ctx, g.ID)
	require.Error(t, err, "a soft-deleted group is not retrievable")
	assert.Empty(t, roles(), "a soft-deleted group confers no inherited roles")
	assert.NotContains(t, sharedSecretIDs(), uint(7), "a soft-deleted group's shares grant nothing")

	// Restore → access returns (grants/memberships were preserved).
	require.NoError(t, ls.RestoreGroup(ctx, g.ID))
	got, err := ls.GetGroup(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, "ops", got.Name)
	assert.Equal(t, []uint{50}, roles(), "restore brings back inherited roles")
	assert.Contains(t, sharedSecretIDs(), uint(7), "restore brings back group shares")
}

// The partial unique index frees a soft-deleted group's name for reuse while still
// blocking two live groups from sharing a name.
func TestGroupSoftDelete_NameReuse(t *testing.T) {
	ls := newGroupSoftDeleteStore(t)
	ctx := context.Background()
	// The production migration creates this; replicate it for the test DB.
	require.NoError(t, ls.db.Exec("CREATE UNIQUE INDEX uniq_groups_name_active ON groups (name) WHERE deleted_at IS NULL").Error)

	g, err := ls.CreateGroup(ctx, &models.Group{Name: "dup"})
	require.NoError(t, err)

	// A second LIVE group with the same name is rejected.
	_, err = ls.CreateGroup(ctx, &models.Group{Name: "dup"})
	require.Error(t, err, "two live groups cannot share a name")

	// After soft-delete, the name is free to reuse.
	require.NoError(t, ls.DeleteGroup(ctx, g.ID))
	_, err = ls.CreateGroup(ctx, &models.Group{Name: "dup"})
	require.NoError(t, err, "a soft-deleted group's name is reusable")
}
