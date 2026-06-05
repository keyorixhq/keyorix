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

// anyAudit stubs the audit write path (every issue/consume/expire writes one).
func anyAudit(ms *MockStorage) {
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).Return(nil)
}

func TestIssueSetupToken(t *testing.T) {
	ctx := context.Background()

	t.Run("returns plaintext once, stores only the hash, supersedes prior tokens", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)

		var captured *models.SetupToken
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeInvitationAccept, "new@acme.io").Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.SetupToken) }).
			Return(&models.SetupToken{ID: 1}, nil)

		res, err := c.IssueSetupToken(ctx, IssueSetupTokenRequest{
			Purpose:      SetupPurposeInvitationAccept,
			SubjectEmail: "New@Acme.io", // normalised to lower-case
			CreatedBy:    7,
		})
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.PlainToken, setupPrefix), "raw token carries the kx_setup_ prefix")
		require.NotNil(t, captured)
		assert.Equal(t, hashSetupToken(res.PlainToken), captured.TokenHash, "stored value is the hash of the plaintext")
		assert.NotEqual(t, res.PlainToken, captured.TokenHash, "plaintext is never stored")
		assert.Equal(t, "new@acme.io", captured.SubjectEmail)
		assert.Equal(t, SetupTokenActive, captured.State)
		ms.AssertCalled(t, "SupersedeActiveSetupTokens", ctx, SetupPurposeInvitationAccept, "new@acme.io")
	})

	t.Run("applies the default TTL when none is configured", func(t *testing.T) {
		ms := new(MockStorage)
		fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
		c := NewKeyorixCore(ms)
		c.now = func() time.Time { return fixed }
		anyAudit(ms)
		var captured *models.SetupToken
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "a@b.io").Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.SetupToken) }).
			Return(&models.SetupToken{ID: 2}, nil)

		_, err := c.IssueSetupToken(ctx, IssueSetupTokenRequest{Purpose: SetupPurposeAccountSetup, SubjectEmail: "a@b.io"})
		require.NoError(t, err)
		assert.Equal(t, fixed.Add(DefaultSetupTokenTTL), captured.ExpiresAt)
	})

	t.Run("honours a configured TTL", func(t *testing.T) {
		ms := new(MockStorage)
		fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
		c := NewKeyorixCore(ms)
		c.now = func() time.Time { return fixed }
		c.SetSetupTokenTTL(2 * time.Hour)
		anyAudit(ms)
		var captured *models.SetupToken
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "a@b.io").Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.SetupToken) }).
			Return(&models.SetupToken{ID: 2}, nil)

		_, err := c.IssueSetupToken(ctx, IssueSetupTokenRequest{Purpose: SetupPurposeAccountSetup, SubjectEmail: "a@b.io"})
		require.NoError(t, err)
		assert.Equal(t, fixed.Add(2*time.Hour), captured.ExpiresAt)
	})

	t.Run("rejects an unknown purpose before any storage call", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		_, err := c.IssueSetupToken(ctx, IssueSetupTokenRequest{Purpose: "wat", SubjectEmail: "a@b.io"})
		require.Error(t, err)
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})

	t.Run("rejects an empty email", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		_, err := c.IssueSetupToken(ctx, IssueSetupTokenRequest{Purpose: SetupPurposeAccountSetup, SubjectEmail: "  "})
		require.Error(t, err)
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})
}

func TestValidateSetupToken(t *testing.T) {
	ctx := context.Background()
	raw := setupPrefix + "abc123"
	hash := hashSetupToken(raw)

	t.Run("resolves an active token for the matching purpose", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		future := c.now().Add(time.Hour)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 5, State: SetupTokenActive, Purpose: SetupPurposeInvitationAccept, ExpiresAt: future,
		}, nil)
		tok, err := c.ValidateSetupToken(ctx, raw, SetupPurposeInvitationAccept)
		require.NoError(t, err)
		assert.Equal(t, uint(5), tok.ID)
	})

	t.Run("rejects (and lazily expires) an overdue token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		past := c.now().Add(-time.Hour)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 5, State: SetupTokenActive, Purpose: SetupPurposeInvitationAccept, ExpiresAt: past,
		}, nil)
		ms.On("MarkSetupTokenExpired", ctx, uint(5)).Return(nil)
		_, err := c.ValidateSetupToken(ctx, raw, SetupPurposeInvitationAccept)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
		ms.AssertCalled(t, "MarkSetupTokenExpired", ctx, uint(5))
	})

	t.Run("rejects a wrong-purpose token (purpose-scoping)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		future := c.now().Add(time.Hour)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 5, State: SetupTokenActive, Purpose: SetupPurposeInvitationAccept, ExpiresAt: future,
		}, nil)
		_, err := c.ValidateSetupToken(ctx, raw, SetupPurposePasswordResetLink)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "purpose")
	})

	t.Run("rejects an already-consumed token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		future := c.now().Add(time.Hour)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(&models.SetupToken{
			ID: 5, State: SetupTokenConsumed, Purpose: SetupPurposeInvitationAccept, ExpiresAt: future,
		}, nil)
		_, err := c.ValidateSetupToken(ctx, raw, SetupPurposeInvitationAccept)
		require.Error(t, err)
		assert.Contains(t, err.Error(), SetupTokenConsumed)
	})

	t.Run("rejects an unknown token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(nil, assert.AnError)
		_, err := c.ValidateSetupToken(ctx, raw, SetupPurposeInvitationAccept)
		require.Error(t, err)
	})
}

func TestConsumeSetupToken(t *testing.T) {
	ctx := context.Background()
	raw := setupPrefix + "xyz789"
	hash := hashSetupToken(raw)

	activeTok := func(c *KeyorixCore) *models.SetupToken {
		return &models.SetupToken{ID: 9, State: SetupTokenActive, Purpose: SetupPurposeAccountSetup, ExpiresAt: c.now().Add(time.Hour)}
	}

	t.Run("consumes an active token exactly once", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeTok(c), nil)
		ms.On("MarkSetupTokenConsumed", ctx, uint(9), mock.AnythingOfType("time.Time")).Return(true, nil)
		tok, err := c.ConsumeSetupToken(ctx, raw, SetupPurposeAccountSetup)
		require.NoError(t, err)
		assert.Equal(t, uint(9), tok.ID)
		ms.AssertCalled(t, "MarkSetupTokenConsumed", ctx, uint(9), mock.AnythingOfType("time.Time"))
	})

	t.Run("rejects a replay that loses the consume race", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeTok(c), nil)
		// The state-guarded UPDATE matched zero rows: someone else already consumed it.
		ms.On("MarkSetupTokenConsumed", ctx, uint(9), mock.AnythingOfType("time.Time")).Return(false, nil)
		_, err := c.ConsumeSetupToken(ctx, raw, SetupPurposeAccountSetup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already used")
	})

	t.Run("does not consume a wrong-purpose token", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSetupTokenByHash", ctx, hash).Return(activeTok(c), nil)
		_, err := c.ConsumeSetupToken(ctx, raw, SetupPurposeInvitationAccept)
		require.Error(t, err)
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
	})
}
