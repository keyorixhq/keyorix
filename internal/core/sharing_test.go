package core

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	if err := i18n.InitializeForTesting(); err != nil {
		panic("failed to initialize i18n for tests: " + err.Error())
	}
	os.Exit(m.Run())
}

func TestKeyorixCore_ShareSecret(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
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
		SharedBy:    1,
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

func TestKeyorixCore_ShareSecret_ValidationError(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test cases
	testCases := []struct {
		name    string
		req     *ShareSecretRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "missing secret ID",
			req: &ShareSecretRequest{
				RecipientID: 2,
				Permission:  "read",
				SharedBy:    1,
			},
			wantErr: true,
		},
		{
			name: "missing recipient ID",
			req: &ShareSecretRequest{
				SecretID:   1,
				Permission: "read",
				SharedBy:   1,
			},
			wantErr: true,
		},
		{
			name: "invalid permission",
			req: &ShareSecretRequest{
				SecretID:    1,
				RecipientID: 2,
				Permission:  "invalid",
				SharedBy:    1,
			},
			wantErr: true,
		},
		{
			name: "missing sharedBy",
			req: &ShareSecretRequest{
				SecretID:    1,
				RecipientID: 2,
				Permission:  "read",
			},
			wantErr: true,
		},
	}

	// Execute and assert
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := core.ShareSecret(ctx, tc.req)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKeyorixCore_ShareSecret_StorageError(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	req := &ShareSecretRequest{
		SecretID:    1,
		RecipientID: 2,
		Permission:  "read",
		SharedBy:    1,
	}

	// Mock expectations - secret not found
	mockStorage.On("GetSecret", ctx, uint(1)).Return(nil, errors.New("secret not found"))

	// Execute
	_, err := core.ShareSecret(ctx, req)

	// Assert
	assert.Error(t, err)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_UpdateSharePermission(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
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
		UpdatedBy:  1,
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

func TestKeyorixCore_RevokeShare(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
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
	err := core.RevokeShare(ctx, 1, 1)

	// Assert
	require.NoError(t, err)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListSharedSecrets(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
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

func TestKeyorixCore_ListSecretShares(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
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

func TestKeyorixCore_ListSharesByUser(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	shares := []*models.ShareRecord{
		{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, Permission: "read"},
		{ID: 2, SecretID: 2, OwnerID: 1, RecipientID: 3, Permission: "write"},
	}

	// Mock expectations
	mockStorage.On("ListSharesByUser", ctx, uint(1)).Return(shares, nil)
	mockStorage.On("ListSharesByOwner", ctx, uint(1)).Return([]*models.ShareRecord{}, nil)

	// Execute
	result, err := core.ListSharesByUser(ctx, 1)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shares, result)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_CheckSharePermission(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
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
