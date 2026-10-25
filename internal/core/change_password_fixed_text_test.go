// change_password_fixed_text_test.go — PG-DRILL-2 / #3543: the refusal ChangePassword
// shows the caller names the broken policy rule, but its text is assembled from fixed
// strings (the rule enum), never from the validator's returned error. CodeQL's
// go/clear-text-logging followed the password-derived validator error through the
// wrapped message into the handler's log call and failed the merge queue; the refusal
// therefore carries no wrapped error at all.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// policyRefusalChain returns every error in err's chain (err first), following
// Unwrap() error only: a refusal built from fixed text has a chain of exactly one.
func policyRefusalChain(err error) []error {
	var chain []error
	for e := err; e != nil; e = errors.Unwrap(e) {
		chain = append(chain, e)
	}
	return chain
}

func TestChangePassword_PolicyRefusalTextIsFixedAndWrapsNothing(t *testing.T) {
	t.Parallel()
	prefix := i18n.T("ErrorValidation", nil) + ": "
	cases := []struct{ name, candidate, want string }{
		{"length", "Sh0rt!aB", "password must be at least 16 characters"},
		{"uppercase", "alllowercase-longpassword1!", "password must contain an uppercase letter"},
		{"lowercase", "ALLUPPERCASE-LONGPASSWORD1!", "password must contain a lowercase letter"},
		{"digit", "NoDigits-HereAtAll-Pass!", "password must contain a digit"},
		{"special", "NoSpecial1CharsHerePassw", "password must contain a special character"},
		{"personal_info", "Alice-Str0ng-Passw0rd!x", "password must not contain your username, email, or display name"},
		{"common_list", "Password1!", "password must be at least 16 characters, not be a commonly-used password"},
		{"several", "short", "password must be at least 16 characters, contain an uppercase letter, contain a digit, contain a special character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newCurrentPasswordCore(t)
			err := c.ChangePassword(context.Background(), 1, curPwOld, tc.candidate, "")
			require.ErrorIs(t, err, ErrPasswordPolicy)
			assert.Equal(t, prefix+tc.want, err.Error())
			assert.Len(t, policyRefusalChain(err), 1, "the refusal wraps no validator error")
		})
	}
}

func TestChangePassword_NamedRefusalsWrapNothing(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	ctx := context.Background()

	err := c.ChangePassword(ctx, 1, curPwOld, curPwOld, "")
	require.ErrorIs(t, err, ErrPasswordPolicy)
	assert.Len(t, policyRefusalChain(err), 1, "current-password resubmission")

	changeTwice(t, c, db)
	err = c.ChangePassword(ctx, 1, curPwThird, curPwNew, "")
	require.ErrorIs(t, err, ErrPasswordReused)
	assert.Len(t, policyRefusalChain(err), 1, "history refusal")
}

// The setup/reset-link path shares the validator: same fixed text, nothing wrapped.
func TestValidateNewPassword_RefusalWrapsNothing(t *testing.T) {
	t.Parallel()
	c, _ := newCurrentPasswordCore(t)
	user, err := c.storage.GetUser(context.Background(), 1)
	require.NoError(t, err)
	err = c.validateNewPassword(context.Background(), user, "short")
	require.ErrorIs(t, err, ErrPasswordPolicy)
	assert.Len(t, policyRefusalChain(err), 1)
}
