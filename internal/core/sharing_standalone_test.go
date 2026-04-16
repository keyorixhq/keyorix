// +build sharing

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

// MockStorage is a mock implementation of the Storage interface for testing
type MockStorageSharing struct {
	mock.Mock
}

func (m *MockStorageSharing) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorageSharing) CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	args := m.Called(ctx, share)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorageSharing) GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	args := m.Called(ctx, shareID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorageSharing) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	args := m.Called(ctx, share)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorageSharing) DeleteShareRecord(ctx context.Context, shareID uint) error {
	args := m.Called(ctx, shareID)
	return args.Error(0)
}

func (m *MockStorageSharing) ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorageSharing) ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretNode), args.Error(1)
}

func (m *MockStorageSharing) CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error) {
	args := m.Called(ctx, secretID, userID)
	return args.String(0), args.Error(1)
}

func (m *MockStorageSharing) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockStorageSharing) CreateSecretAccessLog(_ context.Context, _ *models.SecretAccessLog) error {
	return nil
}

func (m *MockStorageSharing) ListNamespaces(_ context.Context) ([]*models.Namespace, error) {
	return nil, nil
}

func (m *MockStorageSharing) ListEnvironments(_ context.Context) ([]*models.Environment, error) {
	return nil, nil
}

func TestSharingMethods(t *testing.T) {
	// i18n is initialized once for the package in TestMain (sharing_test.go)
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	// Note: do not defer ResetForTesting here — TestMain owns the i18n lifecycle for this package

	t.Run("ShareSecret", testShareSecret)
	t.Run("UpdateSharePermission", testUpdateSharePermission)
	t.Run("RevokeShare", testRevokeShare)
	t.Run("ListSharedSecrets", testListSharedSecrets)
	t.Run("ListSecretShares", testListSecretShares)
	t.Run("CheckSharePermission", testCheckSharePermission)
}

func testShareSecret(t *testing.T) {
	// Setup
	mockStorage := new(MockStorageSharing)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
	}
	req := &ShareSecretRequest{
		SecretID:    1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
		SharedBy:    "user1",
	}

	// Mock expectations
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	mockStorage.On("CreateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(shareRecord, nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	// Execute
	result, err := core.ShareSecret(ctx, req)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shareRecord, result)
	mockStorage.AssertExpectations(t)
}

func testUpdateSharePermission(t *testing.T) {
	// Setup
	mockStorage := new(MockStorageSharing)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
	}
	updatedShareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "write", // Updated permission
	}
	req := &UpdateShareRequest{
		ShareID:    1,
		Permission: "write",
		UpdatedBy:  "user1",
	}

	// Mock expectations
	mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	mockStorage.On("UpdateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(updatedShareRecord, nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	// Execute
	result, err := core.UpdateSharePermission(ctx, req)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, updatedShareRecord, result)
	mockStorage.AssertExpectations(t)
}

func testRevokeShare(t *testing.T) {
	// Setup
	mockStorage := new(MockStorageSharing)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
	}

	// Mock expectations
	mockStorage.On("GetShareRecord", ctx, uint(1)).Return(shareRecord, nil)
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	mockStorage.On("DeleteShareRecord", ctx, uint(1)).Return(nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	// Execute
	err := core.RevokeShare(ctx, 1, "user1")

	// Assert
	require.NoError(t, err)
	mockStorage.AssertExpectations(t)
}

func testListSharedSecrets(t *testing.T) {
	// Setup
	mockStorage := new(MockStorageSharing)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	secrets := []*models.SecretNode{
		{ID: 1, Name: "secret1"},
		{ID: 2, Name: "secret2"},
	}

	// Mock expectations
	mockStorage.On("ListSharedSecrets", ctx, uint(1)).Return(secrets, nil)

	// Execute
	result, err := core.ListSharedSecrets(ctx, 1)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, secrets, result)
	mockStorage.AssertExpectations(t)
}

func testListSecretShares(t *testing.T) {
	// Setup
	mockStorage := new(MockStorageSharing)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	secret := &models.SecretNode{
		ID:      1,
		Name:    "test-secret",
		OwnerID: 1,
	}
	shares := []*models.ShareRecord{
		{ID: 1, SecretID: 1, RecipientID: 2, Permission: "read"},
		{ID: 2, SecretID: 1, RecipientID: 3, Permission: "write"},
	}

	// Mock expectations
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	mockStorage.On("ListSharesBySecret", ctx, uint(1)).Return(shares, nil)

	// Execute
	result, err := core.ListSecretShares(ctx, 1)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shares, result)
	mockStorage.AssertExpectations(t)
}

func testCheckSharePermission(t *testing.T) {
	// Setup
	mockStorage := new(MockStorageSharing)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Mock expectations
	mockStorage.On("CheckSharePermission", ctx, uint(1), uint(2)).Return("read", nil)

	// Execute
	permission, err := core.CheckSharePermission(ctx, 1, 2)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "read", permission)
	mockStorage.AssertExpectations(t)
}