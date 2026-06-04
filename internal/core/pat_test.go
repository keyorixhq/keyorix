package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateOwnPAT(t *testing.T) {
	ctx := context.Background()

	t.Run("returns plaintext once and stores only the hash", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		var captured *models.PersonalAccessToken
		ms.On("CreatePersonalAccessToken", ctx, mock.AnythingOfType("*models.PersonalAccessToken")).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.PersonalAccessToken) }).
			Return(&models.PersonalAccessToken{ID: 1}, nil)

		res, err := c.CreateOwnPAT(ctx, 1, "ci-token", nil)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.PlainToken, patPrefix), "raw token carries the kx_pat_ prefix")
		require.NotNil(t, captured)
		assert.Equal(t, hashPAT(res.PlainToken), captured.TokenHash, "stored value is the hash of the plaintext")
		assert.NotEqual(t, res.PlainToken, captured.TokenHash, "plaintext is never stored")
		assert.True(t, strings.HasPrefix(captured.TokenPrefix, patPrefix))
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		_, err := c.CreateOwnPAT(ctx, 1, "   ", nil)
		require.Error(t, err)
		ms.AssertNotCalled(t, "CreatePersonalAccessToken", mock.Anything, mock.Anything)
	})
}

func TestValidatePATToken(t *testing.T) {
	ctx := context.Background()
	raw := patPrefix + "abc123def456"
	hash := hashPAT(raw)

	t.Run("resolves a valid token to its user and roles", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1}, nil)
		ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: acctTestUser, IsActive: true}, nil)
		ms.On("TouchPersonalAccessToken", ctx, uint(9), mock.AnythingOfType("time.Time"), patTouchInterval).Return(nil)
		role := "system_viewer"
		ms.On("GetUserRoles", ctx, uint(1)).Return([]*models.Role{{Name: role}}, nil)

		user, roles, err := c.ValidatePATToken(ctx, raw)
		require.NoError(t, err)
		assert.Equal(t, uint(1), user.ID)
		assert.Equal(t, []string{role}, roles)
	})

	t.Run("rejects a revoked token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1, Revoked: true}, nil)
		_, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("rejects an expired token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		past := time.Now().Add(-time.Hour)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1, ExpiresAt: &past}, nil)
		_, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("rejects a token for an inactive user", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(&models.PersonalAccessToken{ID: 9, UserID: 1}, nil)
		ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, IsActive: false}, nil)
		_, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "inactive")
	})

	t.Run("rejects an unknown token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByHash", ctx, hash).Return(nil, assert.AnError)
		_, _, err := c.ValidatePATToken(ctx, raw)
		require.Error(t, err)
	})

	t.Run("rejects a non-PAT token before any storage lookup", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		_, _, err := c.ValidatePATToken(ctx, "some-session-token")
		require.Error(t, err)
		ms.AssertNotCalled(t, "GetPersonalAccessTokenByHash", mock.Anything, mock.Anything)
	})
}

func TestRevokeOwnPAT(t *testing.T) {
	ctx := context.Background()

	t.Run("revokes a token the caller owns", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByID", ctx, uint(3)).Return(&models.PersonalAccessToken{ID: 3, UserID: 1}, nil)
		ms.On("RevokePersonalAccessToken", ctx, uint(3)).Return(nil)
		require.NoError(t, c.RevokeOwnPAT(ctx, 1, 3))
		ms.AssertCalled(t, "RevokePersonalAccessToken", ctx, uint(3))
	})

	t.Run("will not revoke another user's token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetPersonalAccessTokenByID", ctx, uint(3)).Return(&models.PersonalAccessToken{ID: 3, UserID: 2}, nil)
		err := c.RevokeOwnPAT(ctx, 1, 3)
		require.Error(t, err)
		ms.AssertNotCalled(t, "RevokePersonalAccessToken", mock.Anything, mock.Anything)
	})
}
