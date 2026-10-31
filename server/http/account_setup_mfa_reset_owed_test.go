// account_setup_mfa_reset_owed_test.go -- #3799 at the HTTP layer: an
// administrator MFA reset sets users.mfa_enrolment_required, and the account-setup
// gate must read it. With security.require_mfa off (or in its upgrade grace
// period) a reset user used to change the one-time password and keep a
// password-only account; now the session is confined to enrolment until a second
// factor is enrolled, and the enrolment clears the flag.
package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

const mfaResetOwedPassword = "Reset#User-Passw0rd-3"

// mfaResetUser creates a local user and applies the full credential reset an
// approved MFA reset applies (core.ResetMFACredentialsInTx, the one definition),
// leaving setupGateOTP as its one-time password.
func (e *setupGateEnv) mfaResetUser(username string) uint {
	e.t.Helper()
	ctx := context.Background()
	u, err := e.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: username + "@example.com", Password: mfaResetOwedPassword,
	})
	require.NoError(e.t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte(setupGateOTP), bcrypt.MinCost)
	require.NoError(e.t, err)
	now := time.Now()
	require.NoError(e.t, e.core.Storage().WithTransaction(ctx, func(tx storage.Storage) error {
		locked, lerr := tx.LockUserForUpdate(ctx, u.ID)
		if lerr != nil {
			return lerr
		}
		_, rerr := core.ResetMFACredentialsInTx(ctx, tx, locked, string(hash), now.Add(time.Hour), now)
		return rerr
	}))
	got, err := e.core.Storage().GetUser(ctx, u.ID)
	require.NoError(e.t, err)
	require.True(e.t, got.MFAEnrolmentRequired, "precondition: the reset marks the enrolment owed")
	return u.ID
}

func TestAccountSetup_MFAResetOwesEnrolment_WithoutRequireMFA(t *testing.T) {
	e := newSetupGateEnvPolicy(t, nil, false)
	ctx := context.Background()
	uid := e.mfaResetUser("reset_user")

	token, challenge := e.passwordLogin("reset_user", setupGateOTP)
	require.Empty(t, challenge, "the reset removed every factor")
	require.NotEmpty(t, token)
	sess, err := e.core.Storage().GetSession(ctx, token)
	require.NoError(t, err)
	assert.True(t, sess.SetupOnly, "a reset user owes both steps: the login must mint a setup-only session")

	r := e.do(http.MethodGet, "/api/v1/projects", token, nil)
	require.Equal(t, http.StatusForbidden, r.status, r.raw)
	assert.Equal(t, []string{core.SetupStepChangePassword, core.SetupStepEnrollMFA}, r.pendingSteps(), r.raw)

	// The password alone does not finish setup.
	r = e.do(http.MethodPost, "/api/v1/auth/change-password", token,
		map[string]string{"current_password": setupGateOTP, "new_password": setupGateNewPassword})
	require.Equal(t, http.StatusOK, r.status, r.raw)
	r = e.do(http.MethodGet, "/api/v1/projects", token, nil)
	require.Equal(t, http.StatusForbidden, r.status, "a reset user reached a normal endpoint without enrolling: %s", r.raw)
	assert.Equal(t, "MFAEnrollmentRequired", r.body["error"], r.raw)
	assert.Equal(t, []string{core.SetupStepEnrollMFA}, r.pendingSteps(), r.raw)

	// A fresh login after the password change is still confined to enrolment.
	token2, challenge := e.passwordLogin("reset_user", setupGateNewPassword)
	require.Empty(t, challenge)
	require.NotEmpty(t, token2)
	r = e.do(http.MethodGet, "/api/v1/projects", token2, nil)
	require.Equal(t, http.StatusForbidden, r.status, "a reset user reached a normal endpoint without enrolling: %s", r.raw)
	assert.Equal(t, "MFAEnrollmentRequired", r.body["error"], r.raw)

	// Enrolling a second factor clears the owed flag and lifts the confinement.
	e.enrolTOTP(token2, setupGateNewPassword)
	u, err := e.core.Storage().GetUser(ctx, uid)
	require.NoError(t, err)
	assert.False(t, u.MFAEnrolmentRequired, "enrolment must clear mfa_enrolment_required")
	assert.True(t, u.MFAEnabled)
	r = e.do(http.MethodGet, "/api/v1/projects", token2, nil)
	assert.Equal(t, http.StatusOK, r.status, "enrolled: the session reaches normal endpoints: %s", r.raw)
}

// A user who was never reset is unaffected: with require_mfa off a password-only
// account reaches normal endpoints, as before.
func TestAccountSetup_NeverResetUser_Unaffected(t *testing.T) {
	e := newSetupGateEnvPolicy(t, nil, false)
	_, err := e.core.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "plain_user", Email: "plain_user@example.com", Password: mfaResetOwedPassword,
	})
	require.NoError(t, err)
	token, challenge := e.passwordLogin("plain_user", mfaResetOwedPassword)
	require.Empty(t, challenge)
	require.NotEmpty(t, token)
	r := e.do(http.MethodGet, "/api/v1/projects", token, nil)
	assert.Equal(t, http.StatusOK, r.status, r.raw)
}
