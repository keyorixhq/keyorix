package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failCreateSessionStorage always fails CreateSession, forcing mintSession to
// fail AFTER whatever single-use value the caller already consumed.
type failCreateSessionStorage struct {
	storage.Storage
}

func (s *failCreateSessionStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	return nil, errors.New("injected fault: CreateSession")
}

// TestVerifyMFALogin_MintFailureAfterConsume_FailsClosed is O4's verification
// for VerifyMFACredentials/VerifyMFALogin, UPDATED for #2567 (FIX-1): a
// failure minting the session AFTER the challenge+TOTP-step are consumed
// must still fail closed for THIS attempt -- no session issued on the
// faulted call. Unlike the original O4 "consume-first" decision (still in
// force for VerifyMFAStepUp's grant creation, see
// TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed below), the LOGIN
// path now releases the just-consumed TOTP step when mintSession fails: a
// storage hiccup unrelated to the code itself must not force the user to
// wait a full ~30s time-step (or worse, lock them out of logging in at all
// if the hiccup persists) to retry a code that was never actually wrong.
// #2567's own text asked for exactly this call to be made, and explicitly
// flagged that the two cases (login vs. step-up) could reasonably differ --
// see this PR's body for why they do: a step-up grant failure leaves the
// caller still fully logged in with the existing session, so consume-first
// costs them only a 15-minute restricted-secret window, not an entire login.
func TestVerifyMFALogin_MintFailureAfterConsume_FailsClosed(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)

	base := c.storage
	c.storage = &failCreateSessionStorage{Storage: base}

	sess, _, err := c.VerifyMFALogin(ctx, ch, code, "ua", "1.2.3.4")
	require.Error(t, err)
	require.Nil(t, sess)

	var sessionCount int64
	require.NoError(t, db.Model(&models.Session{}).Count(&sessionCount).Error)
	assert.Zero(t, sessionCount, "a mint failure after consume must issue NO session")

	// #2567: the TOTP step is released on a mint failure -- a retry with a
	// FRESH challenge and the SAME code (fault now removed) must succeed,
	// proving the user isn't locked out of their own account by a storage
	// hiccup that had nothing to do with their code.
	c.storage = base
	ch2, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess2, _, err := c.VerifyMFALogin(ctx, ch2, code, "ua", "1.2.3.4")
	require.NoError(t, err, "the TOTP step must be usable again once the earlier mint failure's fault clears")
	require.NotNil(t, sess2)
}

// TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed is O4's
// verification for verifyMFAStepUpCode/VerifyMFAStepUp: a failure creating
// the MFAStepUpGrant AFTER the TOTP step is consumed must fail closed -- no
// grant issued, code stays consumed.
func TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	base := c.storage
	c.storage = &failCreateMFAStepUpGrantStorage{Storage: base}

	err = c.VerifyMFAStepUp(ctx, 1, code)
	require.Error(t, err)

	var grantCount int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Count(&grantCount).Error)
	assert.Zero(t, grantCount, "a grant-creation failure after consume must issue NO grant")

	// The TOTP step stayed consumed: a retry with the SAME code (fault removed)
	// is still refused.
	c.storage = base
	err = c.VerifyMFAStepUp(ctx, 1, code)
	require.Error(t, err, "the TOTP step must stay consumed even though the earlier grant-creation failed")
}

type failCreateMFAStepUpGrantStorage struct {
	storage.Storage
}

func (s *failCreateMFAStepUpGrantStorage) CreateMFAStepUpGrant(ctx context.Context, g *models.MFAStepUpGrant) error {
	return errors.New("injected fault: CreateMFAStepUpGrant")
}

// TestFinishWebAuthnLogin_MintFailureAfterConsume_FailsClosed is O4's
// verification for FinishWebAuthnLogin: a failure minting the session AFTER
// the MFA challenge + WebAuthn session are consumed must fail closed -- no
// session issued, and both consumed values stay consumed (replay refused).
func TestFinishWebAuthnLogin_MintFailureAfterConsume_FailsClosed(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	base := c.storage
	c.storage = &failCreateSessionStorage{Storage: base}

	session, user, err := c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	require.Nil(t, session)
	require.Nil(t, user)

	var sessionCount int64
	require.NoError(t, db.Model(&models.Session{}).Count(&sessionCount).Error)
	assert.Zero(t, sessionCount, "a mint failure after consume must issue NO session")

	// Both the MFA challenge and the WebAuthn ceremony session stay consumed
	// even though the mint failed -- a replay (fault removed) is still refused.
	c.storage = base
	_, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err, "the challenge/session pair must stay consumed even though the earlier mint failed")
}

// TestFinishWebAuthnPasswordlessLogin_MintFailureAfterConsume_FailsClosed
// mirrors the above for the passwordless path (no MFA challenge, only the
// discoverable-login WebAuthn session).
func TestFinishWebAuthnPasswordlessLogin_MintFailureAfterConsume_FailsClosed(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = specWebAuthnID(1)
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)

	base := c.storage
	c.storage = &failCreateSessionStorage{Storage: base}

	session, user, err := c.FinishWebAuthnPasswordlessLogin(ctx, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	require.Nil(t, session)
	require.Nil(t, user)

	var sessionCount int64
	require.NoError(t, db.Model(&models.Session{}).Count(&sessionCount).Error)
	assert.Zero(t, sessionCount, "a mint failure after consume must issue NO session")
}

// TestFinishWebAuthnReauth_GrantFailureAfterConsume_FailsClosed is O4's
// verification for FinishWebAuthnReauth: a failure creating the
// MFAStepUpGrant AFTER the WebAuthn reauth session is consumed must fail
// closed -- no grant issued, session stays consumed (replay refused). No
// existing test covered FinishWebAuthnReauth at all before this.
func TestFinishWebAuthnReauth_GrantFailureAfterConsume_FailsClosed(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, webauthnReauthSessionPurpose, &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	base := c.storage
	c.storage = &failCreateMFAStepUpGrantStorage{Storage: base}

	err = c.FinishWebAuthnReauth(ctx, 1, token, parsed)
	require.Error(t, err)

	var grantCount int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Count(&grantCount).Error)
	assert.Zero(t, grantCount, "a grant-creation failure after consume must issue NO grant")

	// The reauth session stays consumed even though the grant creation failed.
	c.storage = base
	err = c.FinishWebAuthnReauth(ctx, 1, token, parsed)
	require.Error(t, err, "the reauth session must stay consumed even though the earlier grant-creation failed")
}
