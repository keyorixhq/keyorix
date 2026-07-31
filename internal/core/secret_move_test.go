package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newMoveFixture opens a unique in-memory SQLite DB and seeds:
//   - User 1 (actor / owner)
//   - Project 1, Environment 1
//   - A secret owned by user 1  (IsSecret=true)
//   - A folder owned by user 1  (IsSecret=false)
//
// Returns the core, the secret ID, the folder ID, and the underlying DB.
func newMoveFixture(t *testing.T) (c *KeyorixCore, secretID, folderID uint, db *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.AuditEvent{},
		&models.ShareRecord{},
		&models.User{},
		&models.Group{},
		&models.UserGroup{},
		&models.UserRole{},
	))

	// Seed a user so share-lookup JOIN does not hit a missing table.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@test.com"}).Error)
	// IsProjectMember gates CheckSecretPermission (RBAC-001); owner must be a member of project 1.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)

	c = &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name:          "db-password",
		ProjectID:     1,
		EnvironmentID: 1,
		Type:          "password",
		OwnerID:       1,
		IsSecret:      true,
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)

	folder, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name:          "infra",
		ProjectID:     1,
		EnvironmentID: 1,
		Type:          "folder",
		OwnerID:       1,
		IsSecret:      false, // folder
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)

	return c, secret.ID, folder.ID, db
}

// TestMoveSecret_ToFolder moves a secret into a valid folder.
func TestMoveSecret_ToFolder(t *testing.T) {
	c, secretID, folderID, _ := newMoveFixture(t)
	ctx := context.Background()

	updated, err := c.MoveSecret(ctx, 1, secretID, &folderID)
	require.NoError(t, err)
	require.NotNil(t, updated.ParentID)
	assert.Equal(t, folderID, *updated.ParentID)
}

// TestMoveSecret_ToRoot moves a secret to the root (nil parent).
func TestMoveSecret_ToRoot(t *testing.T) {
	c, secretID, folderID, _ := newMoveFixture(t)
	ctx := context.Background()

	// First move into a folder, then back to root.
	_, err := c.MoveSecret(ctx, 1, secretID, &folderID)
	require.NoError(t, err)

	updated, err := c.MoveSecret(ctx, 1, secretID, nil)
	require.NoError(t, err)
	assert.Nil(t, updated.ParentID)
}

// TestMoveSecret_ToRoot_ZeroParentID treats parent_id=0 as root (nil parent).
func TestMoveSecret_ToRoot_ZeroParentID(t *testing.T) {
	c, secretID, _, _ := newMoveFixture(t)
	ctx := context.Background()

	zero := uint(0)
	updated, err := c.MoveSecret(ctx, 1, secretID, &zero)
	require.NoError(t, err)
	assert.Nil(t, updated.ParentID)
}

// TestMoveSecret_NonFolderParent rejects moving into a secret (not a folder).
func TestMoveSecret_NonFolderParent(t *testing.T) {
	c, secretID, _, _ := newMoveFixture(t)
	ctx := context.Background()

	// The secret itself is IsSecret=true — trying to use it as a parent fails.
	_, err := c.MoveSecret(ctx, 1, secretID, &secretID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "itself")
}

// TestMoveSecret_NonFolder_OtherSecret rejects using another secret as parent.
func TestMoveSecret_NonFolder_OtherSecret(t *testing.T) {
	c, secretID, _, db := newMoveFixture(t)
	ctx := context.Background()

	// Create a second secret (IsSecret=true) to use as an invalid parent.
	other, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name:          "other-secret",
		ProjectID:     1,
		EnvironmentID: 1,
		Type:          "password",
		OwnerID:       1,
		IsSecret:      true,
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)
	_ = db

	_, err = c.MoveSecret(ctx, 1, secretID, &other.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a folder")
}

// TestMoveSecret_SecretNotFound returns an error when the secret does not exist.
func TestMoveSecret_SecretNotFound(t *testing.T) {
	c, _, _, _ := newMoveFixture(t)
	ctx := context.Background()

	_, err := c.MoveSecret(ctx, 1, 9999, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestMoveSecret_ParentNotFound returns a validation error when the parent does not exist.
func TestMoveSecret_ParentNotFound(t *testing.T) {
	c, secretID, _, _ := newMoveFixture(t)
	ctx := context.Background()

	nonExistentParent := uint(9999)
	_, err := c.MoveSecret(ctx, 1, secretID, &nonExistentParent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestMoveSecret_AuditEvent verifies that an audit event is written after a successful move.
func TestMoveSecret_AuditEvent(t *testing.T) {
	c, secretID, folderID, db := newMoveFixture(t)
	ctx := context.Background()

	_, err := c.MoveSecret(ctx, 1, secretID, &folderID)
	require.NoError(t, err)

	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventSecretMoved).Count(&count).Error)
	assert.EqualValues(t, 1, count)
}

// TestMoveSecret_AuditEvent_ToRoot verifies that moving to root is also audited.
func TestMoveSecret_AuditEvent_ToRoot(t *testing.T) {
	c, secretID, _, db := newMoveFixture(t)
	ctx := context.Background()

	_, err := c.MoveSecret(ctx, 1, secretID, nil)
	require.NoError(t, err)

	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventSecretMoved).Count(&count).Error)
	assert.EqualValues(t, 1, count)
}

// TestMoveSecret_ZeroActorID rejects a zero actor ID (validation).
func TestMoveSecret_ZeroActorID(t *testing.T) {
	c, secretID, _, _ := newMoveFixture(t)
	ctx := context.Background()

	_, err := c.MoveSecret(ctx, 0, secretID, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestMoveSecret_ZeroSecretID rejects a zero secret ID (validation).
func TestMoveSecret_ZeroSecretID(t *testing.T) {
	c, _, _, _ := newMoveFixture(t)
	ctx := context.Background()

	_, err := c.MoveSecret(ctx, 1, 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestMoveFolder_ToAnotherFolder moves a folder node into a sibling folder.
func TestMoveFolder_ToAnotherFolder(t *testing.T) {
	c, _, folderID, db := newMoveFixture(t)
	ctx := context.Background()

	// Create a second folder to be the target parent.
	target, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "target-folder", ProjectID: 1, EnvironmentID: 1,
		Type: "folder", OwnerID: 1, IsSecret: false, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_ = db

	// Move the first folder into the target folder.
	updated, err := c.MoveSecret(ctx, 1, folderID, &target.ID)
	require.NoError(t, err)
	require.NotNil(t, updated.ParentID)
	assert.Equal(t, target.ID, *updated.ParentID)
}
