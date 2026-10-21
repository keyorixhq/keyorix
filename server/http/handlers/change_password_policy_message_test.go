// change_password_policy_message_test.go — POST /auth/change-password tells the
// caller which password-policy rule the new password broke. Found by PG-DRILL-1:
// a one-time-password user choosing a password that contained their own username
// got "an internal error occurred; please try again or contact support" (HTTP 400)
// and the real reason only in the server log.
package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChangePassword_PolicyRefusalNamesTheRule(t *testing.T) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)

	// The test user is "alice" / alice@example.com: a password containing the
	// username breaks the personal-information rule.
	w := changePasswordAs(t, h, lockoutOracleTestPassword, "Alice-Str0ng-Passw0rd!x")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "must not contain", "the caller must be told which rule failed")
	require.NotContains(t, w.Body.String(), "internal error")
}
