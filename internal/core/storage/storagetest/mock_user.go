package storagetest

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateUser ignores the optional plaintextPassword variadic (#499) — it is not
// forwarded to m.Called, so existing `.On("CreateUser", ctx, user)`
// expectations (2 args) keep matching regardless of what core passes.
func (m *MockStorage) CreateUser(ctx context.Context, user *models.User, _ ...string) (*models.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if !m.mockHasExpectation("GetUser") {
		return nil, errMockLookupNotStubbed
	}
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// LockUserForUpdate has no row lock in the mock; it reuses the GetUser expectation.
// Unstubbed, it answers "not found" as storage.ErrUserNotFound, like the other
// lookup-only getters (mockHasExpectation): every grant transaction now row-locks
// its user first (NAMEDLOCK-OVERLAP-2 fences), and a test about something else
// should not have to stub that.
func (m *MockStorage) LockUserForUpdate(ctx context.Context, id uint) (*models.User, error) {
	if !m.mockHasExpectation("GetUser") {
		return nil, fmt.Errorf("%w: %w", errMockLookupNotStubbed, storage.ErrUserNotFound)
	}
	return m.GetUser(ctx, id)
}

func (m *MockStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) UpdateUserIfActiveStateMatches(ctx context.Context, user *models.User, fromActive bool) (bool, error) {
	args := m.Called(ctx, user, fromActive)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error {
	args := m.Called(ctx, userID, loginAt)
	return args.Error(0)
}

func (m *MockStorage) SetAccountState(ctx context.Context, id uint, state string, updatedAt time.Time) error {
	args := m.Called(ctx, id, state, updatedAt)
	return args.Error(0)
}

func (m *MockStorage) SetAccountStateIfMatches(ctx context.Context, id uint, fromState, toState string, updatedAt time.Time) (bool, error) {
	args := m.Called(ctx, id, fromState, toState, updatedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ClaimUserExternalIDIfUnset(ctx context.Context, id uint, externalID string, updatedAt time.Time) (bool, error) {
	args := m.Called(ctx, id, externalID, updatedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) SetPasswordHash(ctx context.Context, id uint, hash string, changedAt time.Time) error {
	args := m.Called(ctx, id, hash, changedAt)
	return args.Error(0)
}

func (m *MockStorage) SetOneTimePasswordExpiry(ctx context.Context, id uint, expiresAt *time.Time, updatedAt time.Time) error {
	args := m.Called(ctx, id, expiresAt, updatedAt)
	return args.Error(0)
}

func (m *MockStorage) UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt, lockedUntil *time.Time, lockoutCount int) error {
	args := m.Called(ctx, id, attempts, lastFailedAt, lockedUntil, lockoutCount)
	return args.Error(0)
}

func (m *MockStorage) DeleteUser(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) RestoreUser(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) ListUsersInStateBefore(ctx context.Context, state string, before time.Time) ([]*models.User, error) {
	args := m.Called(ctx, state, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) ListInactiveUsers(ctx context.Context, threshold time.Time) ([]*models.User, error) {
	args := m.Called(ctx, threshold)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) CreateUserWithRoleGrants(ctx context.Context, user *models.User, grants []storage.RoleGrant) (*models.User, error) {
	args := m.Called(ctx, user, grants)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error) {
	args := m.Called(ctx, externalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) AddPasswordHistory(ctx context.Context, userID uint, hash string, at time.Time) error {
	args := m.Called(ctx, userID, hash, at)
	return args.Error(0)
}

func (m *MockStorage) RecentPasswordHashes(ctx context.Context, userID uint, limit int) ([]string, error) {
	args := m.Called(ctx, userID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) PrunePasswordHistory(ctx context.Context, userID uint, keep int) error {
	args := m.Called(ctx, userID, keep)
	return args.Error(0)
}
