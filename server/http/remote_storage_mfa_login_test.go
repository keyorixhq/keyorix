package http

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogin_RemoteStorage_ProxiesMFACredentialCheck proves the #509 fix for the
// second-factor half of storage.type: remote login: a "spoke" server backed by
// RemoteStorage, pointed at a real "hub" server backed by LocalStorage, can now
// complete a TOTP-protected login end-to-end (up to the SAME pre-existing
// session-persistence gap #506's own test documents, #508 — see below), proxied
// via core.RemoteMFAVerifier (internal/core/mfa.go) and POST
// /api/v1/users/{id}/mfa-challenge + POST /api/v1/users/verify-mfa
// (server/http/handlers/users_crud.go).
//
// Before this fix, EVERY storage method mfa.go relies on (GetMFASecret,
// CreateMFAChallenge, ConsumeMFAChallenge, MarkTOTPStepUsed, ...) was an
// unconditional stub on RemoteStorage, so a "spoke" deployment could not even
// ISSUE a challenge, let alone verify one — an MFA-enabled account could not
// complete login at all under storage.type: remote. This test proves that is no
// longer true: a challenge can be issued, a wrong code is rejected, a correct
// code's CHECK now genuinely succeeds (proceeding past that gate into
// mintSession — blocked only by the separate, pre-existing #508 gap, exactly
// like #506's own password-only test), and repeated wrong codes trip the SAME
// per-account lockout the direct LocalStorage path enforces.
func TestLogin_RemoteStorage_ProxiesMFACredentialCheck(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// --- upstream ("hub"): the real holder of the user record + TOTP secret ---
	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	upstreamCore.SetAuthEncryptor(enc)

	ctx := context.Background()

	// A dedicated MFA-enabled user, distinct from the admin service-credential
	// identity (upstreamToken/"testadmin") — enrolling MFA purges every existing
	// session for the enrolled user (mfa.go's ActivateMFA), so reusing the same
	// account here would invalidate the very token this test authenticates the
	// RemoteStorage client with.
	const mfaPassword = "Zq8#Trn4$Vhx2@Wp!"
	mfaUser, err := upstreamCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "mfauser", Email: "mfauser@example.com", DisplayName: "MFA User", Password: mfaPassword,
	})
	require.NoError(t, err)

	_, totpSecret, err := upstreamCore.BeginMFAEnrollment(ctx, mfaUser.ID)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, err)
	_, err = upstreamCore.ActivateMFA(ctx, mfaUser.ID, actCode, mfaPassword)
	require.NoError(t, err)

	// A tight lockout policy (2 attempts) so this test can trip it in a handful
	// of calls below, proving the SAME per-account lockout gating the direct
	// LocalStorage path enforces also applies via this proxied path (#509's
	// primary security concern) — not a parallel, unprotected check.
	upstreamCore.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 2, Window: 15 * time.Minute,
		BaseCooldown: time.Hour, MaxCooldown: time.Hour,
	})

	cfg := &config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	// --- downstream ("spoke"): storage.type: remote, pointed at the upstream ---
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstreamCore := core.NewKeyorixCore(rs)

	// Password step: the account requires MFA, so Login must report
	// ErrMFARequired (proxied via the #506 fix) rather than returning a session
	// or a bare error — proving the password-verification proxy correctly
	// surfaces MFAEnabled even under storage.type: remote.
	_, loginUser, err := downstreamCore.Login(ctx, &core.LoginRequest{Username: "mfauser", Password: mfaPassword})
	require.ErrorIs(t, err, core.ErrMFARequired)
	require.NotNil(t, loginUser)
	assert.True(t, loginUser.MFAEnabled)

	// Second-factor step: issue a challenge via the (#509) proxy.
	challenge, err := downstreamCore.CreateMFAChallenge(ctx, loginUser.ID)
	require.NoError(t, err)
	require.NotEmpty(t, challenge)

	// A wrong code must fail through the proxied path exactly like it always
	// has — the credential check itself rejects it before ever reaching session
	// minting.
	_, _, err = downstreamCore.VerifyMFALogin(ctx, challenge, "000000", "test-agent", "203.0.113.1")
	require.Error(t, err)
	assert.Equal(t, "invalid code", err.Error())

	// The CORRECT code now gets PAST the credential check (the #509 fix) —
	// proceeding to mintSession, which fails on a DIFFERENT, session-specific
	// error (the same pre-existing session-persistence gap #506's own test
	// documents, #508), not the generic "invalid code" every failure reason
	// collapsed to before this fix. A fresh challenge is required: the previous
	// one was consumed above.
	challenge2, err := downstreamCore.CreateMFAChallenge(ctx, loginUser.ID)
	require.NoError(t, err)
	correctCode, err := totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, err)
	_, _, err = downstreamCore.VerifyMFALogin(ctx, challenge2, correctCode, "test-agent", "203.0.113.1")
	require.Error(t, err, "session persistence is a separate, unimplemented gap (#508) — "+
		"but the error must no longer be the generic credential-check failure")
	assert.NotEqual(t, "invalid code", err.Error(),
		"a CORRECT TOTP code must be distinguishable from a wrong one: it should fail at session "+
			"minting, not at the credential check the #509 fix targets")
	assert.Contains(t, err.Error(), "session", "expected a session-persistence failure, not a credential-check failure")

	// --- lockout: repeated wrong codes via THIS proxied path must trip the SAME
	// per-account lockout the direct path enforces (MaxAttempts=2 above),
	// proving it is not a parallel, unprotected credential check — #509's
	// primary security concern. Verified directly against the upstream's own
	// (LocalStorage-backed) user record, since VerifyMFALogin's return error
	// alone can't distinguish "wrong code" from "locked" through this proxy
	// (deliberate, mirroring #506's collapse).
	ch1, err := downstreamCore.CreateMFAChallenge(ctx, loginUser.ID)
	require.NoError(t, err)
	_, _, err = downstreamCore.VerifyMFALogin(ctx, ch1, "111111", "test-agent", "203.0.113.1")
	require.Error(t, err)

	ch2, err := downstreamCore.CreateMFAChallenge(ctx, loginUser.ID)
	require.NoError(t, err)
	_, _, err = downstreamCore.VerifyMFALogin(ctx, ch2, "222222", "test-agent", "203.0.113.1")
	require.Error(t, err)

	locked, err := upstreamCore.GetUser(ctx, mfaUser.ID)
	require.NoError(t, err)
	require.NotNil(t, locked.LoginLockedUntil, "the account must be locked upstream after "+
		"MaxAttempts failed second-factor attempts reached via the proxied path, exactly like "+
		"the direct LocalStorage path")
	assert.True(t, locked.LoginLockedUntil.After(time.Now()))

	// While locked, even a fresh challenge + the CORRECT code must be refused —
	// proxied through the identical path.
	ch3, err := downstreamCore.CreateMFAChallenge(ctx, loginUser.ID)
	require.NoError(t, err)
	lockedCode, lerr := totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, lerr)
	_, _, err = downstreamCore.VerifyMFALogin(ctx, ch3, lockedCode, "test-agent", "203.0.113.1")
	require.Error(t, err)
}
