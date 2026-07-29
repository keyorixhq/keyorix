package core

import (
	"context"
	"errors"
	"testing"
	"time"

	stg "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newOwnershipCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

// setupOwnerPermission makes secretID owned by actorID so EnforceSecretReadPermission passes.
func setupOwnerPermission(store *MockStorage, ctx context.Context, secretID, actorID uint) {
	store.On("GetSecret", ctx, secretID).
		Return(&models.SecretNode{ID: secretID, OwnerID: actorID}, nil)
	// CheckSecretPermission gates the owner fast-path on IsProjectMember (RBAC-001).
	store.On("IsProjectMember", mock.Anything, actorID, uint(0)).Return(true, nil)
}

func TestGetSecretOwnershipHistory_Empty(t *testing.T) {
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	setupOwnerPermission(store, ctx, 100, 42)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{}, int64(0), nil)

	records, err := c.GetSecretOwnershipHistory(ctx, 100, 42)
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestGetSecretOwnershipHistory_ParsesOwnershipDescription(t *testing.T) {
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	actor := uint(42)
	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	setupOwnerPermission(store, ctx, 100, actor)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{
			{
				ID:          7,
				EventTime:   ts,
				UserID:      &actor,
				Description: `transferred ownership of secret "alpha" from user 5 to user 10`,
			},
		}, int64(1), nil)

	records, err := c.GetSecretOwnershipHistory(ctx, 100, actor)
	require.NoError(t, err)
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, uint(7), rec.EventID)
	assert.Equal(t, ts, rec.ChangedAt)
	assert.Equal(t, actor, rec.ChangedBy)
	assert.Equal(t, uint(5), rec.FromID)
	assert.Equal(t, uint(10), rec.ToID)
}

func TestGetSecretOwnershipHistory_InvalidDescriptionKeepsZeroIDs(t *testing.T) {
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	actor := uint(42)
	setupOwnerPermission(store, ctx, 100, actor)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{
			{
				ID:          8,
				EventTime:   time.Now(),
				Description: "some legacy event without from/to pattern",
			},
		}, int64(1), nil)

	records, err := c.GetSecretOwnershipHistory(ctx, 100, actor)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, uint(0), records[0].FromID)
	assert.Equal(t, uint(0), records[0].ToID)
}

func TestGetSecretOwnershipHistory_MultipleRecordsPreserveOrder(t *testing.T) {
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	actor := uint(42)
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	setupOwnerPermission(store, ctx, 100, actor)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return([]*models.AuditEvent{
			{ID: 1, EventTime: t1, Description: `transferred ownership of secret "x" from user 1 to user 2`},
			{ID: 2, EventTime: t2, Description: `transferred ownership of secret "x" from user 2 to user 3`},
		}, int64(2), nil)

	records, err := c.GetSecretOwnershipHistory(ctx, 100, actor)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, uint(1), records[0].EventID)
	assert.Equal(t, uint(2), records[1].EventID)
}

func TestGetSecretOwnershipHistory_PermissionDenied(t *testing.T) {
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	// GetSecret returns secret owned by user 99, not actorID 42.
	store.On("GetSecret", ctx, uint(100)).
		Return(&models.SecretNode{ID: 100, OwnerID: 99}, nil)
	// CheckSecretPermission also checks shares when not the owner.
	store.On("ListSharesBySecret", ctx, uint(100)).
		Return([]*models.ShareRecord{}, nil)
	// CheckGroupPermissions → GetUserGroups needed.
	store.On("GetUserGroups", ctx, uint(42)).Return([]*models.Group{}, nil)
	// RBAC fallback (r124): no roles → deny.
	store.On("GetUserRoleIDsAt", mock.Anything, uint(42), mock.Anything).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", mock.Anything, uint(42), mock.Anything).Return([]uint{}, nil)

	_, err := c.GetSecretOwnershipHistory(ctx, 100, 42)
	require.Error(t, err)
}

func TestGetSecretOwnershipHistory_AuditLogsError(t *testing.T) {
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	setupOwnerPermission(store, ctx, 100, 42)
	store.On("GetAuditLogs", ctx, mock.AnythingOfType("*storage.AuditFilter")).
		Return(nil, int64(0), errors.New("db error"))

	_, err := c.GetSecretOwnershipHistory(ctx, 100, 42)
	require.Error(t, err)
}

// Ensure the filter produced by GetSecretOwnershipHistory uses the correct action type.
func TestGetSecretOwnershipHistory_FilterUsesOwnerTransferredAction(t *testing.T) {
	store := new(MockStorage)
	c := newOwnershipCore(store)
	ctx := context.Background()

	setupOwnerPermission(store, ctx, 100, 42)

	capturedAction := ""
	store.On("GetAuditLogs", ctx, mock.MatchedBy(func(f *stg.AuditFilter) bool {
		if f != nil && f.Action != nil {
			capturedAction = *f.Action
		}
		return true
	})).Return([]*models.AuditEvent{}, int64(0), nil)

	_, err := c.GetSecretOwnershipHistory(ctx, 100, 42)
	require.NoError(t, err)
	assert.Equal(t, EventSecretOwnerTransferred, capturedAction)
}
