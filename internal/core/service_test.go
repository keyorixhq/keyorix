package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)



func TestKeyorixCore_CreateSecret(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	// Create mock storage
	mockStorage := new(MockStorage)
	core := NewKeyorixCore(mockStorage)

	ctx := context.Background()

	t.Run("successful secret creation", func(t *testing.T) {
		req := &CreateSecretRequest{
			Name:          "test-secret",
			Value:         []byte("secret-value"),
			NamespaceID:   1,
			ZoneID:        1,
			EnvironmentID: 1,
			Type:          "password",
			CreatedBy:     "test-user",
		}

		expectedSecret := &models.SecretNode{
			ID:            1,
			Name:          req.Name,
			NamespaceID:   req.NamespaceID,
			ZoneID:        req.ZoneID,
			EnvironmentID: req.EnvironmentID,
			Type:          req.Type,
			CreatedBy:     req.CreatedBy,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		expectedVersion := &models.SecretVersion{
			ID:            1,
			SecretNodeID:  1,
			VersionNumber: 1,
			EncryptedValue: req.Value,
			CreatedAt:     time.Now(),
		}

		// Mock storage calls
		mockStorage.On("GetSecretByName", ctx, req.Name, req.NamespaceID, req.ZoneID, req.EnvironmentID).Return(nil, assert.AnError)
		mockStorage.On("CreateSecret", ctx, mock.AnythingOfType("*models.SecretNode")).Return(expectedSecret, nil)
		mockStorage.On("CreateSecretVersion", ctx, mock.AnythingOfType("*models.SecretVersion")).Return(expectedVersion, nil)

		// Execute
		result, err := core.CreateSecret(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedSecret.Name, result.Name)
		assert.Equal(t, expectedSecret.Type, result.Type)
		mockStorage.AssertExpectations(t)
	})

	t.Run("validation error - missing name", func(t *testing.T) {
		req := &CreateSecretRequest{
			Name:          "", // Missing name
			Value:         []byte("secret-value"),
			NamespaceID:   1,
			ZoneID:        1,
			EnvironmentID: 1,
			Type:          "password",
			CreatedBy:     "test-user",
		}

		// Execute
		result, err := core.CreateSecret(ctx, req)

		// Assert
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "Validation error") // i18n translated error
		assert.Contains(t, err.Error(), "Name")             // i18n translated field name
	})

	t.Run("secret already exists", func(t *testing.T) {
		req := &CreateSecretRequest{
			Name:          "existing-secret",
			Value:         []byte("secret-value"),
			NamespaceID:   1,
			ZoneID:        1,
			EnvironmentID: 1,
			Type:          "password",
			CreatedBy:     "test-user",
		}

		existingSecret := &models.SecretNode{
			ID:   1,
			Name: req.Name,
		}

		// Mock storage calls
		mockStorage.On("GetSecretByName", ctx, req.Name, req.NamespaceID, req.ZoneID, req.EnvironmentID).Return(existingSecret, nil)

		// Execute
		result, err := core.CreateSecret(ctx, req)

		// Assert
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "Secret already exists") // i18n translated error
		mockStorage.AssertExpectations(t)
	})
}

func TestKeyorixCore_GetSecret(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	ctx := context.Background()

	t.Run("successful secret retrieval", func(t *testing.T) {
		// Create fresh mock storage for this test
		mockStorage := new(MockStorage)
		core := NewKeyorixCore(mockStorage)

		secretID := uint(1)
		expectedSecret := &models.SecretNode{
			ID:        secretID,
			Name:      "test-secret",
			Type:      "password",
			CreatedAt: time.Now(),
		}

		// Mock storage call
		mockStorage.On("GetSecret", ctx, secretID).Return(expectedSecret, nil)

		// Execute
		result, err := core.GetSecret(ctx, secretID)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedSecret.ID, result.ID)
		assert.Equal(t, expectedSecret.Name, result.Name)
		mockStorage.AssertExpectations(t)
	})

	t.Run("secret not found", func(t *testing.T) {
		// Create fresh mock storage for this test
		mockStorage := new(MockStorage)
		core := NewKeyorixCore(mockStorage)

		secretID := uint(999)

		// Mock storage call
		mockStorage.On("GetSecret", ctx, secretID).Return(nil, assert.AnError)

		// Execute
		result, err := core.GetSecret(ctx, secretID)

		// Assert
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "Secret not found") // i18n translated error
		mockStorage.AssertExpectations(t)
	})

	t.Run("expired secret", func(t *testing.T) {
		// Create fresh mock storage for this test
		mockStorage := new(MockStorage)
		core := NewKeyorixCore(mockStorage)

		secretID := uint(1)
		expiredTime := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
		expiredSecret := &models.SecretNode{
			ID:         secretID,
			Name:       "expired-secret",
			Expiration: &expiredTime,
		}

		// Mock storage call
		mockStorage.On("GetSecret", ctx, secretID).Return(expiredSecret, nil)

		// Execute
		result, err := core.GetSecret(ctx, secretID)

		// Assert
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "Secret has expired") // i18n translated error
		mockStorage.AssertExpectations(t)
	})

	t.Run("validation error - zero ID", func(t *testing.T) {
		// Create fresh mock storage for this test
		mockStorage := new(MockStorage)
		core := NewKeyorixCore(mockStorage)

		secretID := uint(0)

		// Execute
		result, err := core.GetSecret(ctx, secretID)

		// Assert
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "Validation error") // i18n translated error
	})
}

func TestKeyorixCore_ListSecrets(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	ctx := context.Background()

	t.Run("successful secret listing", func(t *testing.T) {
		// Create fresh mock storage for this test
		mockStorage := new(MockStorage)
		core := NewKeyorixCore(mockStorage)

		filter := &storage.SecretFilter{
			Page:     1,
			PageSize: 10,
		}

		expectedSecrets := []*models.SecretNode{
			{ID: 1, Name: "secret-1"},
			{ID: 2, Name: "secret-2"},
		}
		expectedTotal := int64(2)

		// Mock storage call
		mockStorage.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).Return(expectedSecrets, expectedTotal, nil)

		// Execute
		secrets, total, err := core.ListSecrets(ctx, filter)

		// Assert
		require.NoError(t, err)
		assert.Len(t, secrets, 2)
		assert.Equal(t, expectedTotal, total)
		assert.Equal(t, "secret-1", secrets[0].Name)
		assert.Equal(t, "secret-2", secrets[1].Name)
		mockStorage.AssertExpectations(t)
	})

	t.Run("default pagination", func(t *testing.T) {
		// Create fresh mock storage for this test
		mockStorage := new(MockStorage)
		core := NewKeyorixCore(mockStorage)

		// Execute with nil filter
		mockStorage.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).Return([]*models.SecretNode{}, int64(0), nil)

		secrets, total, err := core.ListSecrets(ctx, nil)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, secrets)
		assert.Equal(t, int64(0), total)
		mockStorage.AssertExpectations(t)
	})
}
