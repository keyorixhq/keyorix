package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestKeyorixCore_ShareSecretWithGroup(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

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
		RecipientID: 2, // Group ID
		IsGroup:     true,
		Permission:  "read",
	}
	req := &GroupShareSecretRequest{
		SecretID:   1,
		GroupID:    2,
		Permission: "read",
		SharedBy:   1,
	}

	// Mock expectations
	mockStorage.On("GetSecret", ctx, uint(1)).Return(secret, nil)
	mockStorage.On("CreateShareRecord", ctx, mock.AnythingOfType("*models.ShareRecord")).Return(shareRecord, nil)
	mockStorage.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	// Execute
	result, err := core.ShareSecretWithGroup(ctx, req)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shareRecord, result)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ShareSecretWithGroup_ValidationError(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test cases
	testCases := []struct {
		name    string
		req     *GroupShareSecretRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "missing secret ID",
			req: &GroupShareSecretRequest{
				GroupID:    2,
				Permission: "read",
				SharedBy:   1,
			},
			wantErr: true,
		},
		{
			name: "missing group ID",
			req: &GroupShareSecretRequest{
				SecretID:   1,
				Permission: "read",
				SharedBy:   1,
			},
			wantErr: true,
		},
		{
			name: "invalid permission",
			req: &GroupShareSecretRequest{
				SecretID:   1,
				GroupID:    2,
				Permission: "invalid",
				SharedBy:   1,
			},
			wantErr: true,
		},
		{
			name: "missing sharedBy",
			req: &GroupShareSecretRequest{
				SecretID:   1,
				GroupID:    2,
				Permission: "read",
			},
			wantErr: true,
		},
	}

	// Execute and assert
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := core.ShareSecretWithGroup(ctx, tc.req)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKeyorixCore_ShareSecretWithGroup_StorageError(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	req := &GroupShareSecretRequest{
		SecretID:   1,
		GroupID:    2,
		Permission: "read",
		SharedBy:   1,
	}

	// Mock expectations - secret not found
	mockStorage.On("GetSecret", ctx, uint(1)).Return(nil, errors.New("secret not found"))

	// Execute
	_, err := core.ShareSecretWithGroup(ctx, req)

	// Assert
	assert.Error(t, err)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListGroupShares(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Test data
	shares := []*models.ShareRecord{
		{ID: 1, SecretID: 1, OwnerID: 1, RecipientID: 2, IsGroup: true, Permission: "read"},
		{ID: 2, SecretID: 2, OwnerID: 1, RecipientID: 2, IsGroup: true, Permission: "write"},
	}

	// Mock expectations
	mockStorage.On("ListSharesByGroup", ctx, uint(2)).Return(shares, nil)

	// Execute
	result, err := core.ListGroupShares(ctx, 2)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, shares, result)
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_ListGroupShares_ValidationError(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Setup
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
	}
	ctx := context.Background()

	// Execute
	_, err = core.ListGroupShares(ctx, 0)

	// Assert
	assert.Error(t, err)
}
