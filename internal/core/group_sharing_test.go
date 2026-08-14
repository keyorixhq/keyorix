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
	stubAuthorizedPrincipal(mockStorage, 1, Scope{}, permSecretsRead)
	mockStorage.On("ListSharesByGroup", ctx, uint(2)).Return(shares, nil)

	// Execute
	result, err := core.ListGroupShares(ctx, ActorTypeUser, 1, 2)

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
	_, err = core.ListGroupShares(ctx, ActorTypeUser, 1, 0)

	// Assert
	assert.Error(t, err)
}

func TestKeyorixCore_ListGroupSharedSecrets(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: func() time.Time { return now }}
	ctx := context.Background()

	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	shares := []*models.ShareRecord{
		{ID: 1, SecretID: 1, RecipientID: 2, IsGroup: true, Permission: "read"},                     // live
		{ID: 2, SecretID: 1, RecipientID: 2, IsGroup: true, Permission: "write"},                    // dup secret → deduped
		{ID: 3, SecretID: 2, RecipientID: 2, IsGroup: true, Permission: "read", ExpiresAt: &past},   // expired → excluded
		{ID: 4, SecretID: 3, RecipientID: 2, IsGroup: true, Permission: "read", ExpiresAt: &future}, // live time-bound
		{ID: 5, SecretID: 4, RecipientID: 2, IsGroup: true, Permission: "read"},                     // secret gone → skipped
	}
	stubAuthorizedPrincipal(ms, 1, Scope{}, permSecretsRead)
	ms.On("ListSharesByGroup", ctx, uint(2)).Return(shares, nil)
	ms.On("GetSecret", ctx, uint(1)).Return(&models.SecretNode{ID: 1, Name: "alpha"}, nil)
	ms.On("GetSecret", ctx, uint(3)).Return(&models.SecretNode{ID: 3, Name: "gamma"}, nil)
	ms.On("GetSecret", ctx, uint(4)).Return((*models.SecretNode)(nil), errors.New("not found"))

	result, err := c.ListGroupSharedSecrets(ctx, ActorTypeUser, 1, 2)
	require.NoError(t, err)

	ids := make([]uint, 0, len(result))
	for _, s := range result {
		ids = append(ids, s.ID)
	}
	assert.Equal(t, []uint{1, 3}, ids, "live + future shares only, deduped, missing skipped")
	// The expired share's secret is never even loaded.
	ms.AssertNotCalled(t, "GetSecret", ctx, uint(2))
}

func TestKeyorixCore_ListGroupSharedSecrets_ValidationError(t *testing.T) {
	c := &KeyorixCore{storage: new(MockStorage), now: time.Now}
	_, err := c.ListGroupSharedSecrets(context.Background(), ActorTypeUser, 1, 0)
	assert.Error(t, err)
}

// Regression (security review): a non-owner must not be able to group-share a
// secret they don't own, even with secrets.write — the owner check in
// ShareSecretWithGroup enforces it (previously missing).
func TestShareSecretWithGroup_NonOwnerDenied(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 1}, nil)

	_, err := c.ShareSecretWithGroup(context.Background(), &GroupShareSecretRequest{
		SecretID: 1, GroupID: 2, Permission: "read", SharedBy: 99, // not the owner
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
	ms.AssertNotCalled(t, "CreateShareRecord", mock.Anything, mock.Anything)
}
