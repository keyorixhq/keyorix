package local

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

func setupTestDB(t *testing.T) (*gorm.DB, *LocalStorage) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	
	// Auto-migrate all required models
	err = db.AutoMigrate(
		&models.User{},
		&models.Group{},
		&models.UserGroup{},
		&models.SecretNode{},
		&models.ShareRecord{},
	)
	require.NoError(t, err)
	
	storage := NewLocalStorage(db)
	return db, storage
}

func createTestUser(t *testing.T, db *gorm.DB, id uint, username string) *models.User {
	user := &models.User{
		ID:        id,
		Username:  username,
		Email:     username + "@example.com",
		CreatedAt: time.Now(),
	}
	err := db.Create(user).Error
	require.NoError(t, err)
	return user
}

func createTestGroup(t *testing.T, db *gorm.DB, id uint, name string) *models.Group {
	group := &models.Group{
		ID:          id,
		Name:        name,
		Description: "Test group",
	}
	err := db.Create(group).Error
	require.NoError(t, err)
	return group
}

func createTestSecret(t *testing.T, db *gorm.DB, id uint, name string, ownerID uint) *models.SecretNode {
	secret := &models.SecretNode{
		ID:            id,
		Name:          name,
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		IsSecret:      true,
		Type:          "password",
		OwnerID:       ownerID,
		CreatedBy:     "test",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	err := db.Create(secret).Error
	require.NoError(t, err)
	return secret
}

func TestCreateShareRecord(t *testing.T) {
	db, storage := setupTestDB(t)
	ctx := context.Background()
	
	// Create test users
	owner := createTestUser(t, db, 1, "owner")
	recipient := createTestUser(t, db, 2, "recipient")
	
	// Create test secret
	secret := createTestSecret(t, db, 1, "test-secret", owner.ID)
	
	// Test creating a share record
	share := &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "read",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	createdShare, err := storage.CreateShareRecord(ctx, share)
	require.NoError(t, err)
	assert.NotNil(t, createdShare)
	assert.NotZero(t, createdShare.ID)
	assert.Equal(t, secret.ID, createdShare.SecretID)
	assert.Equal(t, owner.ID, createdShare.OwnerID)
	assert.Equal(t, recipient.ID, createdShare.RecipientID)
	assert.Equal(t, "read", createdShare.Permission)
	
	// Test creating a duplicate share record (should update)
	duplicateShare := &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "write", // Changed permission
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	updatedShare, err := storage.CreateShareRecord(ctx, duplicateShare)
	require.NoError(t, err)
	assert.Equal(t, createdShare.ID, updatedShare.ID) // Same ID (updated)
	assert.Equal(t, "write", updatedShare.Permission) // Updated permission
	
	// Test creating a share with non-existent secret
	invalidShare := &models.ShareRecord{
		SecretID:    999, // Non-existent
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "read",
	}
	
	_, err = storage.CreateShareRecord(ctx, invalidShare)
	assert.Error(t, err)
	
	// Test creating a share with non-existent recipient
	invalidShare = &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: 999, // Non-existent
		IsGroup:     false,
		Permission:  "read",
	}
	
	_, err = storage.CreateShareRecord(ctx, invalidShare)
	assert.Error(t, err)
	
	// Test creating a share with wrong owner
	invalidShare = &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     recipient.ID, // Not the owner
		RecipientID: owner.ID,
		IsGroup:     false,
		Permission:  "read",
	}
	
	_, err = storage.CreateShareRecord(ctx, invalidShare)
	assert.Error(t, err)
}

func TestGetShareRecord(t *testing.T) {
	db, storage := setupTestDB(t)
	ctx := context.Background()
	
	// Create test users
	owner := createTestUser(t, db, 1, "owner")
	recipient := createTestUser(t, db, 2, "recipient")
	
	// Create test secret
	secret := createTestSecret(t, db, 1, "test-secret", owner.ID)
	
	// Create a share record
	share := &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "read",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	err := db.Create(share).Error
	require.NoError(t, err)
	
	// Test getting the share record
	retrievedShare, err := storage.GetShareRecord(ctx, share.ID)
	require.NoError(t, err)
	assert.Equal(t, share.ID, retrievedShare.ID)
	assert.Equal(t, share.SecretID, retrievedShare.SecretID)
	assert.Equal(t, share.OwnerID, retrievedShare.OwnerID)
	assert.Equal(t, share.RecipientID, retrievedShare.RecipientID)
	assert.Equal(t, share.Permission, retrievedShare.Permission)
	
	// Test getting a non-existent share record
	_, err = storage.GetShareRecord(ctx, 999)
	assert.Error(t, err)
}

func TestUpdateShareRecord(t *testing.T) {
	db, storage := setupTestDB(t)
	ctx := context.Background()
	
	// Create test users
	owner := createTestUser(t, db, 1, "owner")
	recipient := createTestUser(t, db, 2, "recipient")
	
	// Create test secret
	secret := createTestSecret(t, db, 1, "test-secret", owner.ID)
	
	// Create a share record
	share := &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "read",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	err := db.Create(share).Error
	require.NoError(t, err)
	
	// Test updating the share record
	updatedShare := &models.ShareRecord{
		ID:         share.ID,
		Permission: "write", // Changed permission
	}
	
	result, err := storage.UpdateShareRecord(ctx, updatedShare)
	require.NoError(t, err)
	assert.Equal(t, share.ID, result.ID)
	assert.Equal(t, "write", result.Permission)
	
	// Test updating a non-existent share record
	invalidShare := &models.ShareRecord{
		ID:         999, // Non-existent
		Permission: "read",
	}
	
	_, err = storage.UpdateShareRecord(ctx, invalidShare)
	assert.Error(t, err)
}

func TestDeleteShareRecord(t *testing.T) {
	db, storage := setupTestDB(t)
	ctx := context.Background()
	
	// Create test users
	owner := createTestUser(t, db, 1, "owner")
	recipient := createTestUser(t, db, 2, "recipient")
	
	// Create test secret
	secret := createTestSecret(t, db, 1, "test-secret", owner.ID)
	
	// Create a share record
	share := &models.ShareRecord{
		ID:          1, // Explicitly set ID for test
		SecretID:    secret.ID,
		OwnerID:     owner.ID,
		RecipientID: recipient.ID,
		IsGroup:     false,
		Permission:  "read",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	err := db.Create(share).Error
	require.NoError(t, err)
	
	// Test deleting the share record
	err = storage.DeleteShareRecord(ctx, share.ID)
	require.NoError(t, err)
	
	// Verify the record is soft deleted (not found in normal query)
	var normalCount int64
	err = db.Model(&models.ShareRecord{}).Where("id = ?", share.ID).Count(&normalCount).Error
	require.NoError(t, err)
	assert.Equal(t, int64(0), normalCount)
	
	// Verify the record exists when using Unscoped
	var unscopedCount int64
	err = db.Unscoped().Model(&models.ShareRecord{}).Where("id = ?", share.ID).Count(&unscopedCount).Error
	require.NoError(t, err)
	assert.Equal(t, int64(1), unscopedCount)
	
	// Test deleting a non-existent share record
	err = storage.DeleteShareRecord(ctx, 999)
	assert.Error(t, err)
}

func TestListSharesBySecret(t *testing.T) {
	db, storage := setupTestDB(t)
	ctx := context.Background()
	
	// Create test users
	owner := createTestUser(t, db, 1, "owner")
	recipient1 := createTestUser(t, db, 2, "recipient1")
	recipient2 := createTestUser(t, db, 3, "recipient2")
	
	// Create test secrets
	secret1 := createTestSecret(t, db, 1, "test-secret-1", owner.ID)
	secret2 := createTestSecret(t, db, 2, "test-secret-2", owner.ID)
	
	// Create share records
	shares := []*models.ShareRecord{
		{
			SecretID:    secret1.ID,
			OwnerID:     owner.ID,
			RecipientID: recipient1.ID,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			SecretID:    secret1.ID,
			OwnerID:     owner.ID,
			RecipientID: recipient2.ID,
			IsGroup:     false,
			Permission:  "write",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			SecretID:    secret2.ID,
			OwnerID:     owner.ID,
			RecipientID: recipient1.ID,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}
	
	for _, share := range shares {
		err := db.Create(share).Error
		require.NoError(t, err)
	}
	
	// Test listing shares for secret1
	secret1Shares, err := storage.ListSharesBySecret(ctx, secret1.ID)
	require.NoError(t, err)
	assert.Len(t, secret1Shares, 2)
	
	// Test listing shares for secret2
	secret2Shares, err := storage.ListSharesBySecret(ctx, secret2.ID)
	require.NoError(t, err)
	assert.Len(t, secret2Shares, 1)
	
	// Test listing shares for non-existent secret
	emptyShares, err := storage.ListSharesBySecret(ctx, 999)
	require.NoError(t, err)
	assert.Empty(t, emptyShares)
}

func TestListSharesByUser(t *testing.T) {
	db, storage := setupTestDB(t)
	ctx := context.Background()
	
	// Create test users
	owner := createTestUser(t, db, 1, "owner")
	recipient1 := createTestUser(t, db, 2, "recipient1")
	recipient2 := createTestUser(t, db, 3, "recipient2")
	
	// Create test secrets
	secret1 := createTestSecret(t, db, 1, "test-secret-1", owner.ID)
	secret2 := createTestSecret(t, db, 2, "test-secret-2", owner.ID)
	
	// Create share records
	shares := []*models.ShareRecord{
		{
			SecretID:    secret1.ID,
			OwnerID:     owner.ID,
			RecipientID: recipient1.ID,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			SecretID:    secret2.ID,
			OwnerID:     owner.ID,
			RecipientID: recipient1.ID,
			IsGroup:     false,
			Permission:  "write",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			SecretID:    secret1.ID,
			OwnerID:     owner.ID,
			RecipientID: recipient2.ID,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}
	
	for _, share := range shares {
		err := db.Create(share).Error
		require.NoError(t, err)
	}
	
	// Test listing shares for recipient1
	recipient1Shares, err := storage.ListSharesByUser(ctx, recipient1.ID)
	require.NoError(t, err)
	assert.Len(t, recipient1Shares, 2)
	
	// Test listing shares for recipient2
	recipient2Shares, err := storage.ListSharesByUser(ctx, recipient2.ID)
	require.NoError(t, err)
	assert.Len(t, recipient2Shares, 1)
	
	// Test listing shares for non-existent user
	emptyShares, err := storage.ListSharesByUser(ctx, 999)
	require.NoError(t, err)
	assert.Empty(t, emptyShares)
}

func TestCheckSharePermission(t *testing.T) {
	db, storage := setupTestDB(t)
	ctx := context.Background()
	
	// Create test users
	owner := createTestUser(t, db, 1, "owner")
	recipient := createTestUser(t, db, 2, "recipient")
	groupMember := createTestUser(t, db, 3, "groupmember")
	nonMember := createTestUser(t, db, 4, "nonmember")
	
	// Create test group
	group := createTestGroup(t, db, 1, "testgroup")
	
	// Add user to group
	userGroup := &models.UserGroup{
		UserID:  groupMember.ID,
		GroupID: group.ID,
	}
	err := db.Create(userGroup).Error
	require.NoError(t, err)
	
	// Create test secrets
	secret1 := createTestSecret(t, db, 1, "test-secret-1", owner.ID)
	secret2 := createTestSecret(t, db, 2, "test-secret-2", owner.ID)
	secret3 := createTestSecret(t, db, 3, "test-secret-3", owner.ID)
	
	// Create share records
	shares := []*models.ShareRecord{
		{
			// Direct user share with read permission
			SecretID:    secret1.ID,
			OwnerID:     owner.ID,
			RecipientID: recipient.ID,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			// Direct user share with write permission
			SecretID:    secret2.ID,
			OwnerID:     owner.ID,
			RecipientID: recipient.ID,
			IsGroup:     false,
			Permission:  "write",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			// Group share
			SecretID:    secret3.ID,
			OwnerID:     owner.ID,
			RecipientID: group.ID,
			IsGroup:     true,
			Permission:  "read",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}
	
	for _, share := range shares {
		err := db.Create(share).Error
		require.NoError(t, err)
	}
	
	// Test owner permission (should always be write)
	permission, err := storage.CheckSharePermission(ctx, secret1.ID, owner.ID)
	require.NoError(t, err)
	assert.Equal(t, "write", permission)
	
	// Test direct read permission
	permission, err = storage.CheckSharePermission(ctx, secret1.ID, recipient.ID)
	require.NoError(t, err)
	assert.Equal(t, "read", permission)
	
	// Test direct write permission
	permission, err = storage.CheckSharePermission(ctx, secret2.ID, recipient.ID)
	require.NoError(t, err)
	assert.Equal(t, "write", permission)
	
	// Test group permission
	permission, err = storage.CheckSharePermission(ctx, secret3.ID, groupMember.ID)
	require.NoError(t, err)
	assert.Equal(t, "read", permission)
	
	// Test no permission
	_, err = storage.CheckSharePermission(ctx, secret1.ID, nonMember.ID)
	assert.Error(t, err)
	
	// Test non-existent secret
	_, err = storage.CheckSharePermission(ctx, 999, owner.ID)
	assert.Error(t, err)
}