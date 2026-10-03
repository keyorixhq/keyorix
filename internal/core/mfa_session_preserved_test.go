package core

// mfa_session_preserved_test.go is the red/green proof for a real bug found
// while fixing #2441/#2442 in the web UI: ActivateMFA and DisableMFA both
// purged EVERY session for the user via deleteSessionsForUserAndEvict(ctx,
// userID, 0, "") -- including the very session that just proved it was the
// account holder (requireReauth's password or TOTP re-authentication) by
// making THIS request. Revoking it too served no security purpose (the
// opposite of ChangePassword's own keepSessionToken precedent, which this
// fix now mirrors), and had a real, live consequence: the web UI's own
// post-activation/post-disable query invalidation (useActivateMfa/
// useDisableMfa's onSuccess, both invalidating the recovery-codes-status
// query) raced the purge, 401'd on the immediate refetch, and forced a
// global logout before the user ever saw the "Save your recovery codes"
// screen -- confirmed live via web/e2e/real/mfa-login.spec.ts's real-backend
// enrollment test, which could not complete until this was fixed.
import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestActivateMFA_KeepsTheCallingSessionButPurgesOthers(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()

	expiry := fixed.Add(time.Hour)
	_, err := c.storage.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "calling-session", ExpiresAt: &expiry})
	require.NoError(t, err)
	_, err = c.storage.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "other-session", ExpiresAt: &expiry})
	require.NoError(t, err)

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)

	_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "calling-session")
	require.NoError(t, err)

	_, err = c.storage.GetSession(ctx, "calling-session")
	require.NoError(t, err, "the calling session must survive ActivateMFA")
	_, err = c.storage.GetSession(ctx, "other-session")
	require.Error(t, err, "every OTHER session must still be purged")
}

func TestActivateMFA_EmptyKeepTokenPurgesEverySession(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()

	expiry := fixed.Add(time.Hour)
	_, err := c.storage.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "some-session", ExpiresAt: &expiry})
	require.NoError(t, err)

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)

	// "" (e.g. a PAT-authenticated caller with no session to keep, or a test
	// that never resolves one) must fall back to the prior, safe behavior:
	// every session purged, same as ChangePassword's own "" fallback.
	_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
	require.NoError(t, err)

	_, err = c.storage.GetSession(ctx, "some-session")
	require.Error(t, err, "an empty keepSessionToken must still purge every session")
}

func TestDisableMFA_KeepsTheCallingSessionButPurgesOthers(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()
	secret, _ := activateMFAForTest(t, c, fixed)

	expiry := fixed.Add(time.Hour)
	_, err := c.storage.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "calling-session", ExpiresAt: &expiry})
	require.NoError(t, err)
	_, err = c.storage.CreateSession(ctx, &models.Session{UserID: 1, SessionToken: "other-session", ExpiresAt: &expiry})
	require.NoError(t, err)

	// MFAEnabled is true now, so requireReauth needs a live code, not the
	// password alone (#372) -- a fresh step, distinct from the one
	// activateMFAForTest already consumed.
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	require.NoError(t, c.DisableMFA(ctx, 1, code, "calling-session"))

	_, err = c.storage.GetSession(ctx, "calling-session")
	require.NoError(t, err, "the calling session must survive DisableMFA")
	_, err = c.storage.GetSession(ctx, "other-session")
	require.Error(t, err, "every OTHER session must still be purged")
}
