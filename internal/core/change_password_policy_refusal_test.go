// change_password_policy_refusal_test.go — PG-DRILL-1 / #3543: ChangePassword names
// the password-policy rule the new password broke, and a refusal that would tell the
// caller something about the account's PAST passwords is charged like a wrong
// current password (review of #3543: the history refusal was a free oracle).
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const curPwThird = "Thirdly#Passw0rd!z"

// assertNoPasswordMaterial fails when err's text carries any of the secrets in play
// or a bcrypt hash.
func assertNoPasswordMaterial(t *testing.T, text string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		assert.NotContains(t, text, s)
	}
	assert.NotContains(t, text, "$2a$")
	assert.NotContains(t, text, "$2b$")
}

// Each policy rule is named in the refusal, which matches ErrPasswordPolicy, is
// not a failed credential (no lockout cost, the password is unchanged) and carries
// none of the passwords.
func TestChangePassword_PolicyRefusalNamesEachRule(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, candidate, rule string }{
		{"length", "Sh0rt!aB", "at least 16 characters"},
		{"uppercase", "alllowercase-longpassword1!", "uppercase letter"},
		{"lowercase", "ALLUPPERCASE-LONGPASSWORD1!", "lowercase letter"},
		{"digit", "NoDigits-HereAtAll-Pass!", "contain a digit"},
		{"special", "NoSpecial1CharsHerePassw", "special character"},
		{"personal_info", "Alice-Str0ng-Passw0rd!x", "not contain your username, email, or display name"},
		{"common_list", "Password1!", "not be a commonly-used password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, db := newCurrentPasswordCore(t)
			err := c.ChangePassword(context.Background(), 1, curPwOld, tc.candidate, "")
			require.Error(t, err)
			require.ErrorIs(t, err, ErrPasswordPolicy)
			require.NotErrorIs(t, err, ErrPasswordReused)
			require.NotErrorIs(t, err, ErrIncorrectCurrentPassword)
			assert.Contains(t, err.Error(), tc.rule)
			assertNoPasswordMaterial(t, err.Error(), tc.candidate, curPwOld)
			assert.Equal(t, lockoutState{}, readLockoutState(t, db, 1), "a policy refusal is not a failed credential")
			assert.True(t, passwordIs(t, db, curPwOld), "nothing changed")
		})
	}
}

// A wrong current password plus a policy-violating new password: the generic
// current-password refusal, no policy text (the policy is not probed without the
// credential, ADR-025), and the failure is counted.
func TestChangePassword_WrongCurrentPasswordHidesPolicyText(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	err := c.ChangePassword(context.Background(), 1, "wrong-guess", "short", "")
	require.ErrorIs(t, err, ErrIncorrectCurrentPassword)
	require.NotErrorIs(t, err, ErrPasswordPolicy)
	assert.NotContains(t, err.Error(), "password must")
	assert.NotContains(t, err.Error(), "characters")
	assert.Equal(t, 1, readLockoutState(t, db, 1).FailedAttempts)
}

// Re-submitting the current password discloses nothing the caller does not hold
// (they just proved they know it): a named policy refusal, free of charge.
func TestChangePassword_CurrentPasswordResubmittedIsNamedAndFree(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	err := c.ChangePassword(context.Background(), 1, curPwOld, curPwOld, "")
	require.ErrorIs(t, err, ErrPasswordPolicy)
	require.NotErrorIs(t, err, ErrPasswordReused)
	assert.Contains(t, err.Error(), "must differ from the current password")
	assertNoPasswordMaterial(t, err.Error(), curPwOld)
	assert.Equal(t, lockoutState{}, readLockoutState(t, db, 1))
}

// changeTwice leaves alice with curPwOld -> curPwNew -> curPwThird applied, so
// curPwNew is a PAST password and curPwThird the current one.
func changeTwice(t *testing.T, c *KeyorixCore, db *gorm.DB) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, c.ChangePassword(ctx, 1, curPwOld, curPwNew, ""))
	require.NoError(t, c.ChangePassword(ctx, 1, curPwNew, curPwThird, ""))
	require.True(t, passwordIs(t, db, curPwThird))
}

// A PAST password is account history the caller may not know. The refusal is
// generic (it names no history, no count, no age), and costs exactly what a wrong
// current password costs on the account counter; MaxAttempts of them lock the
// account, which then refuses even the correct current password.
func TestChangePassword_HistoryReuseIsChargedLikeAWrongPassword(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	changeTwice(t, c, db)
	ctx := context.Background()

	// Control: what one wrong current password costs.
	cc, cdb := newCurrentPasswordCore(t)
	require.ErrorIs(t, cc.ChangePassword(ctx, 1, "wrong-guess", curPwNew, ""), ErrIncorrectCurrentPassword)
	control := readLockoutState(t, cdb, 1)
	require.Equal(t, 1, control.FailedAttempts)

	err := c.ChangePassword(ctx, 1, curPwThird, curPwNew, "")
	require.ErrorIs(t, err, ErrPasswordReused)
	require.ErrorIs(t, err, ErrPasswordPolicy, "a history refusal is also a policy refusal")
	require.NotErrorIs(t, err, ErrIncorrectCurrentPassword)
	assert.Contains(t, err.Error(), "cannot be used")
	for _, word := range []string{"recent", "previous", "history", "reuse", "used before", "old"} {
		assert.NotContains(t, err.Error(), word, "the wording must not describe the account's history")
	}
	assertNoPasswordMaterial(t, err.Error(), curPwNew, curPwThird, curPwOld)
	assert.Equal(t, control, readLockoutState(t, db, 1), "one history probe costs what one wrong current password costs")
	assert.True(t, passwordIs(t, db, curPwThird), "the refused change changed nothing")

	for range postVerdictParityPolicy.MaxAttempts - 1 {
		require.ErrorIs(t, c.ChangePassword(ctx, 1, curPwThird, curPwNew, ""), ErrPasswordReused)
	}
	assert.True(t, readLockoutState(t, db, 1).Locked, "MaxAttempts history probes lock the account like wrong passwords")
	err = c.ChangePassword(ctx, 1, curPwThird, "Fourthly#Passw0rd!w", "")
	require.ErrorIs(t, err, ErrIncorrectCurrentPassword, "locked: even the right current password is refused, answered like a wrong one")
	assert.True(t, passwordIs(t, db, curPwThird))
}

// The charge is audited without the candidate, and a successful change after
// refusals is not charged (existing behaviour: success clears the counter).
func TestChangePassword_HistoryReuseIsAuditedWithoutPasswordMaterial(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	changeTwice(t, c, db)
	ctx := context.Background()

	require.ErrorIs(t, c.ChangePassword(ctx, 1, curPwThird, curPwNew, ""), ErrPasswordReused)
	DrainBackgroundGoroutines()
	var ev []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "auth.password_reuse_refused").Find(&ev).Error)
	require.Len(t, ev, 1)
	require.NotNil(t, ev[0].UserID)
	assert.EqualValues(t, 1, *ev[0].UserID)
	require.NotNil(t, ev[0].Success)
	assert.False(t, *ev[0].Success, "a refusal is a failure event")
	assertNoPasswordMaterial(t, ev[0].Description, curPwNew, curPwThird, curPwOld)

	require.NoError(t, c.ChangePassword(ctx, 1, curPwThird, "Fourthly#Passw0rd!w", ""))
	assert.Equal(t, lockoutState{}, readLockoutState(t, db, 1), "a committed change clears the counter, as before")
}

// With the history rule off, nothing is looked up, named or charged.
func TestChangePassword_HistoryRuleOffDisclosesNothing(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	changeTwice(t, c, db)
	c.passwordPolicy.HistoryCount = 0
	require.NoError(t, c.ChangePassword(context.Background(), 1, curPwThird, curPwNew, ""))
	assert.Equal(t, lockoutState{}, readLockoutState(t, db, 1))
}

func passwordIs(t *testing.T, db *gorm.DB, password string) bool {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
}
