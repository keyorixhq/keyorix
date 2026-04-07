package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCheckSecretPermission(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Helper function to create test secret
	createTestSecret := func(id, ownerID uint, name string) *models.SecretNode {
		return &models.SecretNode{
			ID:      id,
			OwnerID: ownerID,
			Name:    name,
		}
	}

	// Helper function to create test share
	createTestShare := func(id, secretID, recipientID uint, permission string, isGroup bool) *models.ShareRecord {
		return &models.ShareRecord{
			ID:          id,
			SecretID:    secretID,
			RecipientID: recipientID,
			IsGroup:     isGroup,
			Permission:  permission,
			CreatedAt:   time.Now(),
		}
	}

	// Helper function to create test group
	createTestGroup := func(id uint, name string) *models.Group {
		return &models.Group{
			ID:   id,
			Name: name,
		}
	}

	tests := []struct {
		name               string
		secretID           uint
		userID             uint
		requiredPermission PermissionLevel
		setupMocks         func(*MockStorage)
		expectedPermission PermissionLevel
		expectedSource     string
		expectError        bool
	}{
		{
			name:               "Owner has full access",
			secretID:           1,
			userID:             1,
			requiredPermission: PermissionRead,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
			},
			expectedPermission: PermissionOwner,
			expectedSource:     "owner",
			expectError:        false,
		},
		{
			name:               "Direct share with read permission",
			secretID:           1,
			userID:             2,
			requiredPermission: PermissionRead,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				share := createTestShare(1, 1, 2, "read", false)
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
			},
			expectedPermission: PermissionRead,
			expectedSource:     "direct_share",
			expectError:        false,
		},
		{
			name:               "Direct share with insufficient permission",
			secretID:           1,
			userID:             2,
			requiredPermission: PermissionWrite,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				share := createTestShare(1, 1, 2, "read", false)
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				ms.On("GetUserGroups", mock.Anything, uint(2)).Return([]*models.Group{}, nil)
			},
			expectError: true,
		},
		{
			name:               "Group share with write permission",
			secretID:           1,
			userID:             3,
			requiredPermission: PermissionWrite,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				groupShare := createTestShare(2, 1, 10, "write", true)
				group := createTestGroup(10, "test-group")
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{groupShare}, nil)
				ms.On("GetUserGroups", mock.Anything, uint(3)).Return([]*models.Group{group}, nil)
			},
			expectedPermission: PermissionWrite,
			expectedSource:     "group_share",
			expectError:        false,
		},
		{
			name:               "No permission",
			secretID:           1,
			userID:             4,
			requiredPermission: PermissionRead,
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
				ms.On("GetUserGroups", mock.Anything, uint(4)).Return([]*models.Group{}, nil)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			tt.setupMocks(mockStorage)

			core := NewKeyorixCore(mockStorage)

			ctx := context.Background()
			permCtx, err := core.CheckSecretPermission(ctx, tt.secretID, tt.userID, tt.requiredPermission)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, permCtx)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, permCtx)
				assert.Equal(t, tt.expectedPermission, permCtx.Permission)
				assert.Equal(t, tt.expectedSource, permCtx.Source)
				assert.Equal(t, tt.secretID, permCtx.SecretID)
				assert.Equal(t, tt.userID, permCtx.UserID)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestHasRequiredPermission(t *testing.T) {
	core := &KeyorixCore{}

	tests := []struct {
		name               string
		userPermission     PermissionLevel
		requiredPermission PermissionLevel
		expected           bool
	}{
		{"Owner can read", PermissionOwner, PermissionRead, true},
		{"Owner can write", PermissionOwner, PermissionWrite, true},
		{"Write can read", PermissionWrite, PermissionRead, true},
		{"Read cannot write", PermissionRead, PermissionWrite, false},
		{"None cannot read", PermissionNone, PermissionRead, false},
		{"Same level allowed", PermissionRead, PermissionRead, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := core.hasRequiredPermission(tt.userPermission, tt.requiredPermission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnforceSecretReadPermission(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	mockStorage := &MockStorage{}
	mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{
		ID:      1,
		OwnerID: 1,
		Name:    "test-secret",
	}, nil)

	core := NewKeyorixCore(mockStorage)

	ctx := context.Background()
	permCtx, err := core.EnforceSecretReadPermission(ctx, 1, 1)

	assert.NoError(t, err)
	assert.NotNil(t, permCtx)
	assert.Equal(t, PermissionOwner, permCtx.Permission)
	assert.Equal(t, "owner", permCtx.Source)

	mockStorage.AssertExpectations(t)
}

func TestEnforceSecretWritePermission(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	mockStorage := &MockStorage{}
	mockStorage.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{
		ID:      1,
		OwnerID: 2,
		Name:    "test-secret",
	}, nil)
	mockStorage.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 1,
			IsGroup:     false,
			Permission:  "read", // Only read permission
			CreatedAt:   time.Now(),
		},
	}, nil)
	mockStorage.On("GetUserGroups", mock.Anything, uint(1)).Return([]*models.Group{}, nil)

	core := NewKeyorixCore(mockStorage)

	ctx := context.Background()
	permCtx, err := core.EnforceSecretWritePermission(ctx, 1, 1)

	assert.Error(t, err) // Should fail because user only has read permission
	assert.Nil(t, permCtx)

	mockStorage.AssertExpectations(t)
}

func TestCanUserModifySecret(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Helper function to create test secret
	createTestSecret := func(id, ownerID uint, name string) *models.SecretNode {
		return &models.SecretNode{
			ID:      id,
			OwnerID: ownerID,
			Name:    name,
		}
	}

	// Helper function to create test share
	createTestShare := func(id, secretID, recipientID uint, permission string) *models.ShareRecord {
		return &models.ShareRecord{
			ID:          id,
			SecretID:    secretID,
			RecipientID: recipientID,
			IsGroup:     false,
			Permission:  permission,
			CreatedAt:   time.Now(),
		}
	}

	tests := []struct {
		name       string
		setupMocks func(*MockStorage)
		expected   bool
	}{
		{
			name: "Owner can modify",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
			},
			expected: true,
		},
		{
			name: "User with write permission can modify",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				share := createTestShare(1, 1, 1, "write")
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
			},
			expected: true,
		},
		{
			name: "User with read permission cannot modify",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				share := createTestShare(1, 1, 1, "read")
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				ms.On("GetUserGroups", mock.Anything, uint(1)).Return([]*models.Group{}, nil)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			tt.setupMocks(mockStorage)

			core := NewKeyorixCore(mockStorage)

			ctx := context.Background()
			canModify, err := core.CanUserModifySecret(ctx, 1, 1)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, canModify)

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestCanUserShareSecret(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Helper function to create test secret
	createTestSecret := func(id, ownerID uint, name string) *models.SecretNode {
		return &models.SecretNode{
			ID:      id,
			OwnerID: ownerID,
			Name:    name,
		}
	}

	// Helper function to create test share
	createTestShare := func(id, secretID, recipientID uint, permission string) *models.ShareRecord {
		return &models.ShareRecord{
			ID:          id,
			SecretID:    secretID,
			RecipientID: recipientID,
			IsGroup:     false,
			Permission:  permission,
			CreatedAt:   time.Now(),
		}
	}

	tests := []struct {
		name       string
		setupMocks func(*MockStorage)
		expected   bool
	}{
		{
			name: "Owner can share",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
			},
			expected: true,
		},
		{
			name: "Non-owner cannot share",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				share := createTestShare(1, 1, 1, "write")
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
				ms.On("GetUserGroups", mock.Anything, uint(1)).Return([]*models.Group{}, nil)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			tt.setupMocks(mockStorage)

			core := NewKeyorixCore(mockStorage)

			ctx := context.Background()
			canShare, err := core.CanUserShareSecret(ctx, 1, 1)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, canShare)

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestGetEffectivePermission(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Helper function to create test secret
	createTestSecret := func(id, ownerID uint, name string) *models.SecretNode {
		return &models.SecretNode{
			ID:      id,
			OwnerID: ownerID,
			Name:    name,
		}
	}

	// Helper function to create test share
	createTestShare := func(id, secretID, recipientID uint, permission string) *models.ShareRecord {
		return &models.ShareRecord{
			ID:          id,
			SecretID:    secretID,
			RecipientID: recipientID,
			IsGroup:     false,
			Permission:  permission,
			CreatedAt:   time.Now(),
		}
	}

	tests := []struct {
		name               string
		setupMocks         func(*MockStorage)
		expectedPermission PermissionLevel
	}{
		{
			name: "Owner has owner permission",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 1, "test-secret")
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
			},
			expectedPermission: PermissionOwner,
		},
		{
			name: "User with write permission",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				share := createTestShare(1, 1, 1, "write")
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
			},
			expectedPermission: PermissionWrite,
		},
		{
			name: "User with no access",
			setupMocks: func(ms *MockStorage) {
				secret := createTestSecret(1, 2, "test-secret")
				
				ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
				ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
				ms.On("GetUserGroups", mock.Anything, uint(1)).Return([]*models.Group{}, nil)
			},
			expectedPermission: PermissionNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			tt.setupMocks(mockStorage)

			core := NewKeyorixCore(mockStorage)

			ctx := context.Background()
			permission, err := core.GetEffectivePermission(ctx, 1, 1)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedPermission, permission)

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestCheckGroupPermissions(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	mockStorage := &MockStorage{}
	core := NewKeyorixCore(mockStorage)

	// Setup user groups
	mockStorage.On("GetUserGroups", mock.Anything, uint(1)).Return([]*models.Group{
		{ID: 10, Name: "group1"},
		{ID: 20, Name: "group2"},
	}, nil)

	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 10, // group1
			IsGroup:     true,
			Permission:  "read",
		},
		{
			ID:          2,
			SecretID:    1,
			RecipientID: 20, // group2
			IsGroup:     true,
			Permission:  "write",
		},
		{
			ID:          3,
			SecretID:    1,
			RecipientID: 30, // group3 (user not a member)
			IsGroup:     true,
			Permission:  "write",
		},
	}

	ctx := context.Background()
	permission, shareID, err := core.CheckGroupPermissions(ctx, 1, 1, shares)

	assert.NoError(t, err)
	assert.Equal(t, PermissionWrite, permission) // Should get highest permission (write)
	assert.NotNil(t, shareID)
	assert.Equal(t, uint(2), *shareID) // Should be the write permission share

	mockStorage.AssertExpectations(t)
}