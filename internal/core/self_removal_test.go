package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRemoveSelfFromShare_Success(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}

	ctx := context.Background()
	secretID := uint(1)
	userID := uint(2)

	// Mock data
	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 2,
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
		},
	}

	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 3,
	}

	// Setup mocks
	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)
	mockStorage.On("GetSecret", ctx, secretID).Return(secret, nil)
	mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	// Execute
	err = core.RemoveSelfFromShare(ctx, secretID, userID)

	// Assert
	assert.NoError(t, err)
	mockStorage.AssertExpectations(t)
}

func TestRemoveSelfFromShare_ShareNotFound(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}

	ctx := context.Background()
	secretID := uint(1)
	userID := uint(2)

	// Mock data - no shares for this user
	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 3, // Different user
			IsGroup:     false,
			Permission:  "read",
			CreatedAt:   time.Now(),
		},
	}

	// Setup mocks
	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)

	// Execute
	err = core.RemoveSelfFromShare(ctx, secretID, userID)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Share not found")
	mockStorage.AssertExpectations(t)
}

func TestRemoveSelfFromShare_ValidationErrors(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}

	ctx := context.Background()

	// Test invalid secret ID
	err = core.RemoveSelfFromShare(ctx, 0, 2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")

	// Test invalid user ID
	err = core.RemoveSelfFromShare(ctx, 1, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestRemoveSelfFromShare_AuditLogging(t *testing.T) {
	// Initialize i18n for testing
	err := i18n.InitializeForTesting()
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}

	ctx := context.Background()
	secretID := uint(1)
	userID := uint(2)

	// Mock data
	shares := []*models.ShareRecord{
		{
			ID:          1,
			SecretID:    1,
			RecipientID: 2,
			IsGroup:     false,
			Permission:  "write",
			CreatedAt:   time.Now(),
		},
	}

	secret := &models.SecretNode{
		ID:      1,
		Name:    "audit-test-secret",
		OwnerID: 3,
	}

	// Setup mocks
	mockStorage.On("ListSharesBySecret", ctx, secretID).Return(shares, nil)
	mockStorage.On("GetSecret", ctx, secretID).Return(secret, nil)
	mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(nil)

	// Verify audit event details
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == "share_self_removed" &&
			event.UserID != nil &&
			*event.UserID == userID &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == secretID &&
			event.Description == "User removed themselves from shared secret (permission: write)"
	})).Return(nil)

	// Execute
	err = core.RemoveSelfFromShare(ctx, secretID, userID)

	// Assert
	assert.NoError(t, err)
	mockStorage.AssertExpectations(t)
}
