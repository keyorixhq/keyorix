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

func newPurgeTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Project{}, &models.Environment{},
		&models.UserRole{}, &models.GroupRole{}, &models.Group{}, &models.UserGroup{}, &models.ShareRecord{},
		&models.PersonalAccessToken{}, &models.Session{}))
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

// TestPurgeDeletedUsersBefore_CascadesDependentRows pins #106: before the fix,
// purging a soft-deleted user only deleted the users row, leaving its UserRole,
// UserGroup, received ShareRecord, PersonalAccessToken, and Session rows orphaned
// forever (nothing else purges them). All five must be gone once the user is purged.
func TestPurgeDeletedUsersBefore_CascadesDependentRows(t *testing.T) {
	ls := newPurgeTestStore(t)
	ctx := context.Background()
	now := time.Now()
	old := now.AddDate(0, 0, -40)
	cutoff := now.AddDate(0, 0, -30)

	require.NoError(t, ls.db.Create(&models.User{ID: 1, Username: "ghost", Email: "g@x"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 2, Username: "owner", Email: "o@x"}).Error)
	require.NoError(t, ls.db.Create(&models.Group{ID: 1, Name: "g1"}).Error)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 1, GroupID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.ShareRecord{SecretID: 1, OwnerID: 2, RecipientID: 1, IsGroup: false}).Error)
	require.NoError(t, ls.db.Create(&models.PersonalAccessToken{UserID: 1, Name: "tok", TokenHash: "h1"}).Error)
	require.NoError(t, ls.db.Create(&models.Session{UserID: 1, SessionToken: "s1"}).Error)
	require.NoError(t, ls.db.Unscoped().Model(&models.User{}).Where("id = ?", 1).Update("deleted_at", old).Error)

	n, err := ls.PurgeDeletedUsersBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	var count int64
	require.NoError(t, ls.db.Model(&models.UserRole{}).Where("user_id = ?", 1).Count(&count).Error)
	assert.Zero(t, count, "UserRole must be purged with the user")
	require.NoError(t, ls.db.Model(&models.UserGroup{}).Where("user_id = ?", 1).Count(&count).Error)
	assert.Zero(t, count, "UserGroup must be purged with the user")
	require.NoError(t, ls.db.Unscoped().Model(&models.ShareRecord{}).Where("recipient_id = ? AND is_group = ?", 1, false).Count(&count).Error)
	assert.Zero(t, count, "a share the user RECEIVED must be purged with the user")
	require.NoError(t, ls.db.Model(&models.PersonalAccessToken{}).Where("user_id = ?", 1).Count(&count).Error)
	assert.Zero(t, count, "PersonalAccessToken must be purged with the user")
	require.NoError(t, ls.db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&count).Error)
	assert.Zero(t, count, "Session must be purged with the user")
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

// Purging a soft-deleted project must also delete the project-scoped role grants
// (UserRole/GroupRole) that reference it — otherwise those rows are permanently
// orphaned (the project ID is gone forever; IDs are never reused), forever
// cluttering every "who has access" report. A global-scope grant (ProjectID 0)
// must survive untouched.
func TestPurgeDeletedProjectsBefore_CascadesRoleGrants(t *testing.T) {
	ls := newPurgeTestStore(t)
	ctx := context.Background()
	old := time.Now().AddDate(0, 0, -40)
	cutoff := time.Now().AddDate(0, 0, -30)

	require.NoError(t, ls.db.Create(&models.Project{ID: 1, Name: "doomed"}).Error)
	require.NoError(t, ls.db.Unscoped().Model(&models.Project{}).Where("id = ?", 1).Update("deleted_at", old).Error)

	// A user-role and a group-role grant scoped to the doomed project…
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 1, RoleID: 1, ProjectID: 1}).Error)
	// …and a global-scope user-role grant (ProjectID 0) that must NOT be touched.
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 2, RoleID: 2, ProjectID: 0}).Error)

	n, err := ls.PurgeDeletedProjectsBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	var orphanedUserRoles, orphanedGroupRoles, globalUserRoles int64
	require.NoError(t, ls.db.Model(&models.UserRole{}).Where("project_id = ?", 1).Count(&orphanedUserRoles).Error)
	assert.Equal(t, int64(0), orphanedUserRoles, "project-scoped UserRole grant must be cleaned up on purge")
	require.NoError(t, ls.db.Model(&models.GroupRole{}).Where("project_id = ?", 1).Count(&orphanedGroupRoles).Error)
	assert.Equal(t, int64(0), orphanedGroupRoles, "project-scoped GroupRole grant must be cleaned up on purge")
	require.NoError(t, ls.db.Model(&models.UserRole{}).Where("project_id = ?", 0).Count(&globalUserRoles).Error)
	assert.Equal(t, int64(1), globalUserRoles, "global-scope grant must survive")
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
