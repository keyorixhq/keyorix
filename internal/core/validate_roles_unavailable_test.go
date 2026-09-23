package core

// validate_roles_unavailable_test.go — regression coverage for #1944.
//
// ValidatePATToken and ValidateSessionToken used to soft-fail a GetUserRoles
// storage error into ([]string{}, nil): a successful-looking validation with
// an empty role list, which the HTTP auth middleware then positively cached as
// UserContext.Roles. Both must now return the distinguishable, retryable
// ErrRoleResolutionUnavailable — and no half-built identity — so the caller
// can answer "retry" instead of silently misreporting the user's roles.

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var errRolesStorageDown = errors.New("pq: connection reset by peer")

func TestValidatePATToken_RolesLookupFailure_ReturnsRetryableError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := patPrefix + "rolesdown1944"

	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetPersonalAccessTokenByHash", ctx, sha256Hex(raw)).Return(&models.PersonalAccessToken{ID: 9, UserID: 1}, nil)
	ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: acctTestUser, IsActive: true, AccountState: AccountActive}, nil)
	ms.On("GetUserRoles", ctx, uint(1)).Return(nil, errRolesStorageDown)

	user, roles, restriction, patID, err := c.ValidatePATToken(ctx, raw)
	require.ErrorIs(t, err, ErrRoleResolutionUnavailable)
	assert.NotErrorIs(t, err, errRolesStorageDown, "the storage error's detail must not be wrapped into the caller-visible error")
	assert.Nil(t, user, "no half-built identity may be returned alongside the error")
	assert.Nil(t, roles)
	assert.Nil(t, restriction)
	assert.Zero(t, patID, "a zero patID keeps the caller from stamping last_used_at for a failed validation")
	assert.NotErrorIs(t, err, ErrPATRevoked)
	assert.NotErrorIs(t, err, ErrPATExpired)
}

func TestValidateSessionToken_RolesLookupFailure_ReturnsRetryableError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSession", ctx, "tok-1944").Return(&models.Session{ID: 7, UserID: 2}, nil)
	ms.On("TouchSession", ctx, uint(7), mock.Anything, mock.Anything).Return(nil)
	ms.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, IsActive: true, AccountState: AccountActive}, nil)
	ms.On("GetUserRoles", ctx, uint(2)).Return(nil, errRolesStorageDown)

	user, roles, err := c.ValidateSessionToken(ctx, "tok-1944")
	require.ErrorIs(t, err, ErrRoleResolutionUnavailable)
	assert.NotErrorIs(t, err, errRolesStorageDown)
	assert.Nil(t, user)
	assert.Nil(t, roles)
}
