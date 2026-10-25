// change_password_policy_message_test.go — POST /auth/change-password tells the
// caller which password-policy rule the new password broke. Found by PG-DRILL-1:
// a one-time-password user choosing a password that contained their own username
// got "an internal error occurred; please try again or contact support" (HTTP 400)
// and the real reason only in the server log.
//
// The review of #3543 added the other half: the refusal must not become an oracle.
// A wrong current password still gets the generic 401 with no policy text; a new
// password found in the password HISTORY is disclosed generically and keeps the
// login-budget slot like a wrong current password; and no response or log line
// carries password material.
package handlers

import (
	"bytes"
	"log"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

const (
	policyMsgThird = "Thirdly#Passw0rd!z"
	// The test user is "alice" / alice@example.com.
	policyMsgPersonal = "Alice-Str0ng-Passw0rd!x"
)

// captureLog collects the standard logger's output for the test.
func captureChangePasswordLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func requireNoPasswordMaterial(t *testing.T, where, text string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		require.NotContains(t, text, s, where)
	}
	require.NotContains(t, text, "$2a$", where)
	require.NotContains(t, text, "$2b$", where)
}

func TestChangePassword_PolicyRefusalNamesTheRule(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)

	w := changePasswordAs(t, h, lockoutOracleTestPassword, policyMsgPersonal)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "must not contain", "the caller must be told which rule failed")
	require.NotContains(t, w.Body.String(), "internal error")
}

// Every rule is named in the 400, free of budget cost, with no password in the
// response or the log.
func TestChangePassword_EachPolicyRuleIsNamed(t *testing.T) {
	cases := []struct{ name, candidate, rule string }{
		{"length", "Sh0rt!aB", "at least 16 characters"},
		{"uppercase", "alllowercase-longpassword1!", "uppercase letter"},
		{"lowercase", "ALLUPPERCASE-LONGPASSWORD1!", "lowercase letter"},
		{"digit", "NoDigits-HereAtAll-Pass!", "contain a digit"},
		{"special", "NoSpecial1CharsHerePassw", "special character"},
		{"personal_info", policyMsgPersonal, "not contain your username, email, or display name"},
		{"common_list", "Password1!", "not be a commonly-used password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureChangePasswordLog(t)
			db := openCurrentPasswordDB(t)
			h := newLoginBudgetHandler(db)
			w := changePasswordAs(t, h, lockoutOracleTestPassword, tc.candidate)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), tc.rule)
			assert.NotContains(t, w.Body.String(), "internal error")
			requireNoPasswordMaterial(t, "response", w.Body.String(), tc.candidate, lockoutOracleTestPassword)
			requireNoPasswordMaterial(t, "log", logs.String(), tc.candidate, lockoutOracleTestPassword)
			// PG-DRILL-2: the refusal is logged as a fixed line, not as the error
			// (go/clear-text-logging followed the error text into the log call).
			assert.Contains(t, logs.String(), "new password refused by policy")
			assert.NotContains(t, logs.String(), tc.rule, "the log line is fixed; the rule text goes only to the caller")
			require.Zero(t, loginAttemptsFor(t, db), "a refused NEW password is not a failed credential")
		})
	}
}

// A wrong current password with a policy-violating new password gets the generic
// 401 and no policy text: the policy is not probed without the credential.
func TestChangePassword_WrongCurrentPasswordGetsTheGeneric401NoPolicyText(t *testing.T) {
	logs := captureChangePasswordLog(t)
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)

	for _, bad := range []string{"short", policyMsgPersonal, "Password1!"} {
		w := changePasswordAs(t, h, "wrong-guess", bad)
		require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "Current password is incorrect")
		for _, leak := range []string{"password must", "characters", "username", "commonly", "uppercase", "digit"} {
			assert.NotContains(t, w.Body.String(), leak)
		}
		requireNoPasswordMaterial(t, "response", w.Body.String(), bad, "wrong-guess")
	}
	requireNoPasswordMaterial(t, "log", logs.String(), "wrong-guess", policyMsgPersonal)
	require.EqualValues(t, 3, loginAttemptsFor(t, db), "each wrong current password keeps its slot")
}

// changePasswordTwice leaves alice's current password at policyMsgThird and
// currentPwNew in her history.
func changePasswordTwice(t *testing.T, h *AuthHandler) {
	t.Helper()
	require.Equal(t, http.StatusOK, changePasswordAs(t, h, lockoutOracleTestPassword, currentPwNew).Code)
	require.Equal(t, http.StatusOK, changePasswordAs(t, h, currentPwNew, policyMsgThird).Code)
}

// A new password found in the password history is refused generically and KEEPS
// the login-budget slot, like a wrong current password: LoginMaxAttempts probes
// spend the IP's budget and the next request is refused with 429 before any check.
func TestChangePassword_HistoryReuseSpendsTheLoginBudget(t *testing.T) {
	logs := captureChangePasswordLog(t)
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	changePasswordTwice(t, h)
	require.Zero(t, loginAttemptsFor(t, db), "successful changes return their slots")

	for i := range core.LoginMaxAttempts {
		w := changePasswordAs(t, h, policyMsgThird, currentPwNew)
		require.Equal(t, http.StatusBadRequest, w.Code, "probe %d: %s", i+1, w.Body.String())
		assert.Contains(t, w.Body.String(), "cannot be used")
		for _, leak := range []string{"recent", "previous", "history", "reuse"} {
			assert.NotContains(t, w.Body.String(), leak, "the wording must not describe the account's history")
		}
		requireNoPasswordMaterial(t, "response", w.Body.String(), currentPwNew, policyMsgThird, lockoutOracleTestPassword)
		require.EqualValues(t, i+1, loginAttemptsFor(t, db), "probe %d must keep its slot", i+1)
	}
	requireNoPasswordMaterial(t, "log", logs.String(), currentPwNew, policyMsgThird, lockoutOracleTestPassword)

	w := changePasswordAs(t, h, policyMsgThird, currentPwNew)
	require.Equal(t, http.StatusTooManyRequests, w.Code, "budget spent: the probe is refused before the check: %s", w.Body.String())
	w = changePasswordAs(t, h, policyMsgThird, "Fourthly#Passw0rd!w")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "and so is a valid change from the same IP: %s", w.Body.String())
}

// Re-submitting the CURRENT password tells the caller nothing new: named, and free.
func TestChangePassword_CurrentPasswordResubmittedIsNamedAndFree(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	w := changePasswordAs(t, h, lockoutOracleTestPassword, lockoutOracleTestPassword)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "must differ from the current password")
	requireNoPasswordMaterial(t, "response", w.Body.String(), lockoutOracleTestPassword)
	require.Zero(t, loginAttemptsFor(t, db))
}

// Existing behaviour: a good change still succeeds, returns its slot and answers
// without any password.
func TestChangePassword_SuccessAnswersWithoutPasswordMaterial(t *testing.T) {
	logs := captureChangePasswordLog(t)
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	w := changePasswordAs(t, h, lockoutOracleTestPassword, currentPwNew)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireNoPasswordMaterial(t, "response", w.Body.String(), currentPwNew, lockoutOracleTestPassword)
	requireNoPasswordMaterial(t, "log", logs.String(), currentPwNew, lockoutOracleTestPassword)
	require.Zero(t, loginAttemptsFor(t, db))
}
