package core

// VALIDATION-TYPED-NOV-1 item 2: the i18n "ErrorValidation" refusals of the users and
// account families match ErrValidation with their text unchanged, so a transport answers
// them 400 / InvalidArgument by errors.Is and not by looking for the translated prefix.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

func TestValidationTyped_UsersAndAccountRefusals(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := NewKeyorixCore(new(MockStorage)) // every case refuses before any storage call
	ctx := context.Background()
	cases := []struct {
		name string
		call func() error
	}{
		{"users/username charset", func() error { return validateUsernameCharset("bad/name") }},
		{"users/username length", func() error { return validateUsernameFormat("ab") }},
		{"users/display name length", func() error { return validateDisplayNameFormat("") }},
		{"users/reissue one-time password for user 0", func() error { _, err := c.ReissueOneTimePassword(ctx, 1, 0); return err }},
		{"account/profile of user 0", func() error { _, err := c.UpdateOwnProfile(ctx, 0, "n", "", ""); return err }},
		{"account/change password of user 0", func() error { return c.ChangePassword(ctx, 0, "a", "b", "") }},
		{"account/list sessions of user 0", func() error { _, err := c.ListOwnSessions(ctx, 0); return err }},
		{"account/revoke session of user 0", func() error { return c.RevokeOwnSession(ctx, 0, 1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrValidation)
			assert.True(t, strings.HasPrefix(err.Error(), i18n.T("ErrorValidation", nil)), "the text is unchanged: %q", err.Error())
			assert.False(t, IsStorageReadUnavailable(err))
		})
	}
}

// A refused new password is a validation refusal too, and keeps matching the password-policy
// and password-reuse sentinels the change-password handler tells apart.
func TestValidationTyped_PasswordPolicyRefusalIsValidation(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	policy := policyRefusal{msg: i18n.T("ErrorValidation", nil) + ": password must be longer"}
	assert.ErrorIs(t, policy, ErrValidation)
	assert.ErrorIs(t, policy, ErrPasswordPolicy)
	assert.NotErrorIs(t, policy, ErrPasswordReused)

	reused := historyRefusal{policyRefusal{msg: i18n.T("ErrorValidation", nil) + ": this password cannot be used; choose a different password"}}
	assert.ErrorIs(t, reused, ErrValidation)
	assert.ErrorIs(t, reused, ErrPasswordPolicy)
	assert.ErrorIs(t, reused, ErrPasswordReused)
}
