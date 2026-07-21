package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newInactivityCore returns a *KeyorixCore backed by a MockStorage with a fixed
// clock, suitable for inactivity-suspend unit tests.
func newInactivityCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

// stubSuspendCall sets up all the mock expectations needed for a successful
// SuspendUser(ctx, 0, userID) call.
func stubSuspendCall(store *MockStorage, ctx context.Context, userID uint) {
	store.On("GetUser", ctx, userID).Return(&models.User{ID: userID, AccountState: AccountActive}, nil)
	store.On("SetAccountState", ctx, userID, AccountSuspended, mock.Anything).Return(nil)
	store.On("ListSessionTokenHashesForUser", ctx, userID).Return([]string{}, nil)
	store.On("DeleteSessionsForUserExcept", ctx, userID, uint(0)).Return(nil)
	store.On("RevokeAllPersonalAccessTokensForUser", ctx, userID).Return([]string{}, nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "account.suspended"
	})).Return(nil)
}

// stubNotAdminCalls sets up IsGlobalAdmin expectations: the user holds no roles.
func stubNotAdminCalls(store *MockStorage, ctx context.Context, userID uint) {
	store.On("GetUserRoleIDsAt", ctx, userID, storage.Scope{}).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, userID, storage.Scope{}).Return([]uint{}, nil)
}

// stubAdminCalls sets up IsGlobalAdmin expectations so the user is a global admin.
// We give them the "admin" role ID and set up GetRoleByName so roleSetContainsAdmin
// finds a match.
func stubAdminCalls(store *MockStorage, ctx context.Context, userID uint) {
	adminRoleID := uint(99)
	store.On("GetUserRoleIDsAt", ctx, userID, storage.Scope{}).Return([]uint{adminRoleID}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, userID, storage.Scope{}).Return([]uint{}, nil)
	// roleSetContainsAdmin iterates adminRoleNames; return an error for non-"admin" names
	// so we don't have to set up all four. For "admin" return the matching role.
	for _, name := range []string{"super_admin", "system_admin", "project_admin"} {
		store.On("GetRoleByName", ctx, name).Return(nil, fmt.Errorf("not found")).Maybe()
	}
	store.On("GetRoleByName", ctx, "admin").Return(&models.Role{ID: adminRoleID, Name: "admin"}, nil)
}

// TestSuspendInactiveUsers_InvalidDays ensures InactiveDays <= 0 is rejected.
func TestSuspendInactiveUsers_InvalidDays(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	for _, days := range []int{0, -1, -100} {
		_, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: days})
		require.Error(t, err, "days=%d should be invalid", days)
		assert.Contains(t, err.Error(), "inactive_days must be greater than 0")
	}
}

// TestSuspendInactiveUsers_EmptyList ensures an empty inactive-user list returns a zero result.
func TestSuspendInactiveUsers_EmptyList(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	// threshold = now - 90 days
	threshold := c.now().Add(-90 * 24 * time.Hour)
	store.On("ListInactiveUsers", ctx, threshold).Return([]*models.User{}, nil)

	res, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Total)
	assert.Equal(t, 0, res.Skipped)
	assert.Empty(t, res.Suspended)
}

// TestSuspendInactiveUsers_InactiveUserSuspended verifies that an inactive user
// returned by ListInactiveUsers is suspended.
func TestSuspendInactiveUsers_InactiveUserSuspended(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-90 * 24 * time.Hour)
	oldLogin := c.now().Add(-100 * 24 * time.Hour)
	user := &models.User{ID: 2, AccountState: AccountActive, LastLoginAt: &oldLogin}
	store.On("ListInactiveUsers", ctx, threshold).Return([]*models.User{user}, nil)

	stubNotAdminCalls(store, ctx, 2)
	stubSuspendCall(store, ctx, 2)

	res, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Total)
	assert.Equal(t, 0, res.Skipped)
	require.Len(t, res.Suspended, 1)
	assert.Equal(t, uint(2), res.Suspended[0])
}

// TestSuspendInactiveUsers_AdminUserSkipped verifies that a global admin who is
// inactive is not suspended.
func TestSuspendInactiveUsers_AdminUserSkipped(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-90 * 24 * time.Hour)
	oldLogin := c.now().Add(-200 * 24 * time.Hour)
	user := &models.User{ID: 3, AccountState: AccountActive, LastLoginAt: &oldLogin}
	store.On("ListInactiveUsers", ctx, threshold).Return([]*models.User{user}, nil)

	stubAdminCalls(store, ctx, 3)

	res, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Total)
	assert.Equal(t, 1, res.Skipped)
	assert.Empty(t, res.Suspended)
}

// TestSuspendInactiveUsers_AlreadySuspendedSkipped ensures an already-suspended
// inactive user is counted as skipped, not re-suspended.
func TestSuspendInactiveUsers_AlreadySuspendedSkipped(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-90 * 24 * time.Hour)
	oldLogin := c.now().Add(-100 * 24 * time.Hour)
	user := &models.User{ID: 4, AccountState: AccountSuspended, LastLoginAt: &oldLogin}
	store.On("ListInactiveUsers", ctx, threshold).Return([]*models.User{user}, nil)

	res, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Total)
	assert.Equal(t, 1, res.Skipped)
	assert.Empty(t, res.Suspended)
}

// TestSuspendInactiveUsers_ListInactiveUsersError verifies that a storage error
// from ListInactiveUsers is propagated.
func TestSuspendInactiveUsers_ListInactiveUsersError(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-30 * 24 * time.Hour)
	store.On("ListInactiveUsers", ctx, threshold).Return(nil, errors.New("db down"))

	_, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 30})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list inactive users")
}

// TestSuspendInactiveUsers_IsAdminError verifies that a storage error while
// checking admin status is propagated.
func TestSuspendInactiveUsers_IsAdminError(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-90 * 24 * time.Hour)
	oldLogin := c.now().Add(-100 * 24 * time.Hour)
	user := &models.User{ID: 7, AccountState: AccountActive, LastLoginAt: &oldLogin}
	store.On("ListInactiveUsers", ctx, threshold).Return([]*models.User{user}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(7), storage.Scope{}).Return(nil, errors.New("storage error"))

	_, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check admin status")
}

// TestSuspendInactiveUsers_SuspendError verifies that a storage error from
// SuspendUser is propagated.
func TestSuspendInactiveUsers_SuspendError(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-90 * 24 * time.Hour)
	oldLogin := c.now().Add(-100 * 24 * time.Hour)
	user := &models.User{ID: 8, AccountState: AccountActive, LastLoginAt: &oldLogin}
	store.On("ListInactiveUsers", ctx, threshold).Return([]*models.User{user}, nil)

	stubNotAdminCalls(store, ctx, 8)
	// GetUser (via LockUserForUpdate) returns error — simulates a suspend failure.
	store.On("GetUser", ctx, uint(8)).Return(nil, errors.New("lock failed"))

	_, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to suspend user")
}

// TestSuspendInactiveUsers_MixedUsers verifies the combined result across
// multiple users in different states.
func TestSuspendInactiveUsers_MixedUsers(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-90 * 24 * time.Hour)
	oldLogin := c.now().Add(-120 * 24 * time.Hour)

	inactiveUser := &models.User{ID: 11, AccountState: AccountActive, LastLoginAt: &oldLogin}
	alreadySuspended := &models.User{ID: 12, AccountState: AccountSuspended, LastLoginAt: &oldLogin}

	// Both are returned by ListInactiveUsers (they are all inactive by definition).
	store.On("ListInactiveUsers", ctx, threshold).
		Return([]*models.User{inactiveUser, alreadySuspended}, nil)

	stubNotAdminCalls(store, ctx, 11)
	stubSuspendCall(store, ctx, 11)

	res, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Total)
	assert.Equal(t, 1, res.Skipped)
	require.Len(t, res.Suspended, 1)
	assert.Equal(t, uint(11), res.Suspended[0])
}

// TestSuspendInactiveUsers_EmptyLegacyAccountState verifies that a user with an
// empty (legacy) account_state treated as active is eligible for suspension.
func TestSuspendInactiveUsers_EmptyLegacyAccountState(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-90 * 24 * time.Hour)
	oldLogin := c.now().Add(-100 * 24 * time.Hour)
	// AccountState="" is legacy-active; should be eligible for suspension.
	user := &models.User{ID: 9, AccountState: "", LastLoginAt: &oldLogin}
	store.On("ListInactiveUsers", ctx, threshold).Return([]*models.User{user}, nil)

	stubNotAdminCalls(store, ctx, 9)
	stubSuspendCall(store, ctx, 9)

	res, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90})
	require.NoError(t, err)
	require.Len(t, res.Suspended, 1)
	assert.Equal(t, uint(9), res.Suspended[0])
}

// TestSuspendInactiveUsers_DryRun verifies that DryRun=true records which users
// would be suspended without actually calling SuspendUser.
func TestSuspendInactiveUsers_DryRun(t *testing.T) {
	store := new(MockStorage)
	c := newInactivityCore(store)
	ctx := context.Background()

	threshold := c.now().Add(-90 * 24 * time.Hour)
	oldLogin := c.now().Add(-100 * 24 * time.Hour)
	user := &models.User{ID: 20, AccountState: AccountActive, LastLoginAt: &oldLogin}
	store.On("ListInactiveUsers", ctx, threshold).Return([]*models.User{user}, nil)

	// Admin check must still run in dry-run mode; set up as non-admin.
	stubNotAdminCalls(store, ctx, 20)
	// SuspendUser must NOT be called — we verify this via AssertNotCalled below.

	res, err := c.SuspendInactiveUsers(ctx, InactivitySuspendConfig{InactiveDays: 90, DryRun: true})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Total)
	assert.Equal(t, 0, res.Skipped)
	require.Len(t, res.Suspended, 1)
	assert.Equal(t, uint(20), res.Suspended[0])

	// Confirm SuspendUser (which would call GetUser/SetAccountState) was never invoked.
	store.AssertNotCalled(t, "GetUser", ctx, uint(20))
	store.AssertNotCalled(t, "SetAccountState", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
