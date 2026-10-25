// setup_consume_reuse_refusal_test.go — review of #3543: CompleteSetup never verifies
// the account's current password, so its refusal of a candidate equal to the current
// password must not be distinguishable from the refusal of a history password (the
// "must differ from the current password" wording is reserved for ChangePassword,
// which verified the current password first).
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCompleteSetup_CurrentAndHistoryPasswordGetOneGenericRefusal(t *testing.T) {
	t.Parallel()
	const (
		currentPw = "Curr3nt!Passw0rd-2026"
		pastPw    = "Pa5t!Passw0rd-2025x"
	)
	ctx := context.Background()
	raw := setupPrefix + "reuse-refusal"
	uid := uint(4)

	hash := func(pw string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
		require.NoError(t, err)
		return string(h)
	}
	refuse := func(candidate string) error {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		anyAudit(ms)
		user := &models.User{ID: uid, Username: "dana", AccountState: AccountActive, PasswordHash: hash(currentPw)}
		ms.On("GetSetupTokenByHash", ctx, sha256Hex(raw)).Return(&models.SetupToken{
			ID: 2, State: SetupTokenActive, Purpose: SetupPurposePasswordResetLink,
			SubjectEmail: "dana@acme.io", SubjectUserID: &uid, ExpiresAt: c.now().Add(1e12),
		}, nil)
		ms.On("GetUser", ctx, uid).Return(user, nil)
		ms.On("RecentPasswordHashes", ctx, uid, 5).Return([]string{hash(pastPw)}, nil)

		_, err := c.CompleteSetup(ctx, raw, candidate, "ua", "1.2.3.4")
		ms.AssertNotCalled(t, "MarkSetupTokenConsumed", mock.Anything, mock.Anything, mock.Anything)
		return err
	}

	errCurrent := refuse(currentPw)
	errPast := refuse(pastPw)
	require.ErrorIs(t, errCurrent, ErrInvalidSetupPassword)
	require.ErrorIs(t, errPast, ErrInvalidSetupPassword)
	assert.Equal(t, errPast.Error(), errCurrent.Error(),
		"a link holder must not be able to tell the current password from a history password")
	assert.NotContains(t, errCurrent.Error(), "current password")
	assertNoPasswordMaterial(t, errCurrent.Error(), currentPw, pastPw)
}
