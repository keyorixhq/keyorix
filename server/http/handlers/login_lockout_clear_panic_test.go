package handlers

// #3556: the lockout clear runs after a login's session insert and Set-Cookie.
// Driven over HTTP through the production middleware.Recovery (postLogin /
// postVerify), so a panic is answered here exactly as a client would see it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// requireDeliveredLogin asserts a 200 whose session cookie names a live
// session and whose login was audited auth.login.
func (e *lockoutOracleEnv) requireDeliveredLogin(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, "a delivered login must answer 200, body %s", w.Body.String())
	var sessionCookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == "kx_session" {
			sessionCookie = c.Value
		}
	}
	require.NotEmpty(t, sessionCookie, "the delivered login must carry its session cookie")
	assert.NotZero(t, e.h.coreService.CurrentSessionID(context.Background(), sessionCookie),
		"the cookie must name a live session")
	assert.Equal(t, int64(1), waitForAuditEvent(t, e.db, "auth.login"),
		"a delivered login must be audited auth.login")
}

// TestLoginDelivery_LockoutClearPanicKeepsTheLoginDelivered is #3556. The clear
// of the failed-login counter (LoginCompletion.Succeeded -> clearLoginFailures
// -> UpdateLoginLockoutState) runs after the session is committed and the
// cookies are set. A panic there used to answer the Recovery 500 that still
// carried a live kx_session cookie, with no auth.login audit: a login reported
// as failed that the client nevertheless held. It is now best-effort, like
// CompleteSSO's clear: the login is delivered (200, cookie, audited) and the
// counter stays where the credential check found it, the strict side.
//
// The counter must be non-zero for the clear to write at all, which is why the
// faultops world (always at 0 failures) never reached this write.
func TestLoginDelivery_LockoutClearPanicKeepsTheLoginDelivered(t *testing.T) {
	armClearPanic := func(e *lockoutOracleEnv) {
		e.fs.Arm(&faultstorage.FaultSpec{
			Method: "UpdateLoginLockoutState", NthCall: 1, Kind: faultstorage.KindPanic, Err: assert.AnError,
		})
	}

	t.Run("login", func(t *testing.T) {
		env := newLockoutOracleEnv(t)
		env.driveToThresholdMinusOne(t)
		armClearPanic(env)
		w := env.postLogin(t, lockoutOracleTestPassword)
		require.True(t, env.fs.Fired(), "the clear must actually have been faulted")
		env.requireDeliveredLogin(t, w)
		obs := env.observe(t, w)
		assert.Equal(t, lockoutOracleMaxAttempts-1, obs.failedAttempts, "an undone clear leaves the counter as the check found it")
		assert.False(t, obs.locked)
	})

	t.Run("mfa_verify", func(t *testing.T) {
		env := newLockoutOracleEnvWithMFA(t)
		env.driveMFAToThresholdMinusOne(t)
		ch, err := env.h.coreService.CreateMFAChallenge(context.Background(), 1)
		require.NoError(t, err)
		code, err := totp.GenerateCode(env.totpSecret, env.clock)
		require.NoError(t, err)
		armClearPanic(env)
		w := env.postVerify(t, ch, code)
		require.True(t, env.fs.Fired(), "the clear must actually have been faulted")
		env.requireDeliveredLogin(t, w)
	})
}
