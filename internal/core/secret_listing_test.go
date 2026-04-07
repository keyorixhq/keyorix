package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestKeyorixCore_ListSecretsWithSharingInfo(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	userID := uint(1)
	filter := &models.SecretListFilter{
		Page:     1,
		PageSize: 10,
	}

	// Mock owned secrets
	ownedSecrets := []*models.SecretNode{
		{
			ID:        1,
			Name:      "owned-secret",
			OwnerID:   userID,
			CreatedAt: time.Now(),
		},
	}

	// Mock shares for owned secret
	ownedSecretShares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			OwnerID:     userID,
			RecipientID: 2,
			Permission:  "read",
		},
	}

	// Mock shared secrets (shares where user is recipient)
	userShares := []*models.ShareRecord{
		{
			ID:          2,
			SecretID:    2,
			OwnerID:     2,
			RecipientID: userID,
			Permission:  "write",
			CreatedAt:   time.Now(),
		},
	}

	sharedSecret := &models.SecretNode{
		ID:        2,
		Name:      "shared-secret",
		OwnerID:   2,
		CreatedAt: time.Now(),
	}

	owner := &models.User{
		ID:       2,
		Username: "owner-user",
	}

	// Mock expectations
	mockStorage.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).Return(ownedSecrets, int64(1), nil)
	mockStorage.On("ListSharesBySecret", ctx, uint(1)).Return(ownedSecretShares, nil)
	mockStorage.On("ListSharesByUser", ctx, userID).Return(userShares, nil)
	mockStorage.On("GetSecret", ctx, uint(2)).Return(sharedSecret, nil)
	mockStorage.On("GetUser", ctx, uint(2)).Return(owner, nil)
	mockStorage.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "testuser"}, nil)

	// Execute
	result, err := core.ListSecretsWithSharingInfo(ctx, userID, filter)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(2), result.Total)
	assert.Equal(t, 1, result.OwnedCount)
	assert.Equal(t, 1, result.SharedCount)
	assert.Len(t, result.Secrets, 2)

	// Check owned secret
	ownedSecretInfo := result.Secrets[0]
	assert.Equal(t, "owned-secret", ownedSecretInfo.Name)
	assert.True(t, ownedSecretInfo.IsOwnedByUser)
	assert.True(t, ownedSecretInfo.IsShared)
	assert.Equal(t, 1, ownedSecretInfo.ShareCount)

	// Check shared secret
	sharedSecretInfo := result.Secrets[1]
	assert.Equal(t, "shared-secret", sharedSecretInfo.Name)
	assert.False(t, sharedSecretInfo.IsOwnedByUser)
	assert.True(t, sharedSecretInfo.IsShared)
	assert.Equal(t, "write", sharedSecretInfo.UserPermission)
	assert.Equal(t, "owner-user", sharedSecretInfo.OwnerUsername)

	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListSecretsWithSharingInfo_ShowOwnedOnly(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	userID := uint(1)
	filter := &models.SecretListFilter{
		Page:          1,
		PageSize:      10,
		ShowOwnedOnly: true,
	}

	// Mock owned secrets
	ownedSecrets := []*models.SecretNode{
		{
			ID:        1,
			Name:      "owned-secret",
			OwnerID:   userID,
			CreatedAt: time.Now(),
		},
	}

	// Mock expectations
	mockStorage.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).Return(ownedSecrets, int64(1), nil)
	mockStorage.On("ListSharesBySecret", ctx, uint(1)).Return([]*models.ShareRecord{}, nil)

	// Execute
	result, err := core.ListSecretsWithSharingInfo(ctx, userID, filter)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, 1, result.OwnedCount)
	assert.Equal(t, 0, result.SharedCount)
	assert.Len(t, result.Secrets, 1)

	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListSecretsWithSharingInfo_ShowSharedOnly(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	userID := uint(1)
	filter := &models.SecretListFilter{
		Page:           1,
		PageSize:       10,
		ShowSharedOnly: true,
	}

	// Mock shared secrets
	userShares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    2,
			OwnerID:     2,
			RecipientID: userID,
			Permission:  "read",
			CreatedAt:   time.Now(),
		},
	}

	sharedSecret := &models.SecretNode{
		ID:        2,
		Name:      "shared-secret",
		OwnerID:   2,
		CreatedAt: time.Now(),
	}

	owner := &models.User{
		ID:       2,
		Username: "owner-user",
	}

	// Mock expectations
	mockStorage.On("ListSharesByUser", ctx, userID).Return(userShares, nil)
	mockStorage.On("GetSecret", ctx, uint(2)).Return(sharedSecret, nil)
	mockStorage.On("GetUser", ctx, uint(2)).Return(owner, nil)
	mockStorage.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "testuser"}, nil)

	// Execute
	result, err := core.ListSecretsWithSharingInfo(ctx, userID, filter)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, 0, result.OwnedCount)
	assert.Equal(t, 1, result.SharedCount)
	assert.Len(t, result.Secrets, 1)

	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_GetSecretSharingStatus(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	secretID := uint(1)
	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    secretID,
			OwnerID:     1,
			RecipientID: 2,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
		},
		{
			ID:          2,
			SecretID:    secretID,
			OwnerID:     1,
			RecipientID: 3,
			IsGroup:     true,
			Permission:  "write",
			CreatedAt:   time.Now(),
		},
	}

	user := &models.User{
		ID:       2,
		Username: "test-user",
	}

	// Mock expectations
	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)
	mockStorage.On("GetUser", ctx, uint(2)).Return(user, nil)
	// GetGroup is NOT called — production code uses fmt.Sprintf("Group %d", id) for groups

	// Execute
	status, err := core.GetSecretSharingStatus(ctx, secretID)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.IsShared)
	assert.Equal(t, 2, status.ShareCount)
	assert.Len(t, status.Shares, 2)

	// Check user share
	userShare := status.Shares[0]
	assert.Equal(t, uint(2), userShare.RecipientID)
	assert.Equal(t, "test-user", userShare.RecipientName)
	assert.False(t, userShare.IsGroup)
	assert.Equal(t, "read", userShare.Permission)

	// Check group share — production code formats group name as "Group <id>"
	groupShare := status.Shares[1]
	assert.Equal(t, uint(3), groupShare.RecipientID)
	assert.Equal(t, "Group 3", groupShare.RecipientName)
	assert.True(t, groupShare.IsGroup)
	assert.Equal(t, "write", groupShare.Permission)

	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_GetUserSecretPermission(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	tests := []struct {
		name           string
		secretID       uint
		userID         uint
		secret         *models.SecretNode
		shares         []*models.ShareRecord
		expectedPerm   string
		expectedSource string
		expectError    bool
	}{
		{
			name:     "user is owner",
			secretID: 1,
			userID:   1,
			secret: &models.SecretNode{
				ID:      1,
				OwnerID: 1,
			},
			expectedPerm:   "owner",
			expectedSource: "owner",
			expectError:    false,
		},
		{
			name:     "user has direct share",
			secretID: 1,
			userID:   2,
			secret: &models.SecretNode{
				ID:      1,
				OwnerID: 1,
			},
			shares: []*models.ShareRecord{
				{
					ID:          1,
					SecretID:    1,
					RecipientID: 2,
					IsGroup:     false,
					Permission:  "read",
				},
			},
			expectedPerm:   "read",
			expectedSource: "direct_share",
			expectError:    false,
		},
		{
			name:     "user has no permission",
			secretID: 1,
			userID:   3,
			secret: &models.SecretNode{
				ID:      1,
				OwnerID: 1,
			},
			shares:      []*models.ShareRecord{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock
			mockStorage.ExpectedCalls = nil

			// Mock expectations
			mockStorage.On("GetSecret", ctx, tt.secretID).Return(tt.secret, nil)
			if tt.secret.OwnerID != tt.userID {
				mockStorage.On("ListSharesBySecret", ctx, tt.secretID).Return(tt.shares, nil)
			}

			// Execute
			perm, err := core.GetUserSecretPermission(ctx, tt.secretID, tt.userID)

			// Assert
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, perm)
			} else {
				require.NoError(t, err)
				require.NotNil(t, perm)
				assert.Equal(t, tt.expectedPerm, perm.Permission)
				assert.Equal(t, tt.expectedSource, perm.Source)
				assert.Equal(t, tt.secretID, perm.SecretID)
				assert.Equal(t, tt.userID, perm.UserID)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}
