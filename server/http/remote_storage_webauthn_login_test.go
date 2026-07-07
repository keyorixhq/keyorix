package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mfaChallengeTokenHash mirrors internal/core.sha256Hex (unexported), which is
// what BeginWebAuthnLogin/FinishWebAuthnLogin actually hash a raw challenge
// token with before ever calling storage.Storage. Duplicated here (rather than
// exported) since this test needs to call RemoteStorage's GetActiveMFAChallenge/
// ConsumeMFAChallenge directly with the SAME hash the core layer would use, to
// exercise the proxy's single-use guarantee without needing a real, signed
// WebAuthn assertion (out of scope for this proxy-focused test).
func mfaChallengeTokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// TestWebAuthnLogin_RemoteStorage_ProxiesMFAChallenge proves the #522 fix: a
// "spoke" server backed by RemoteStorage, pointed at a real "hub" server backed
// by LocalStorage, can now complete the WebAuthn-as-second-factor login's
// challenge-resolution step (BeginWebAuthnLogin) end-to-end, and that the
// challenge's single-use consume (FinishWebAuthnLogin's first step) is atomic
// across the HTTP hop — proxied via the NEW GetActiveMFAChallenge/
// ConsumeMFAChallenge routes (server/http/handlers/users_crud.go), distinct
// from #509's already-working TOTP proxy (verify-mfa/mfa-challenge) and #517's
// already-working WebAuthn CREDENTIAL CRUD proxy (webauthn_proxy.go) — neither
// of which this bug touched.
//
// Before this fix, GetActiveMFAChallenge/ConsumeMFAChallenge were unconditional
// stubs on RemoteStorage, so BeginWebAuthnLogin/FinishWebAuthnLogin failed
// immediately with "operation not supported in remote (client) mode" for EVERY
// WebAuthn-as-second-factor login attempt under storage.type: remote.
func TestWebAuthnLogin_RemoteStorage_ProxiesMFAChallenge(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// --- upstream ("hub"): the real holder of the user record + WebAuthn rows ---
	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	rp, err := webauthn.New(&webauthn.Config{
		RPID: "localhost", RPDisplayName: "Keyorix", RPOrigins: []string{"https://localhost"},
	})
	require.NoError(t, err)
	upstreamCore.SetWebAuthn(rp)

	ctx := context.Background()

	waUser, err := upstreamCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "wauser", Email: "wauser@example.com", DisplayName: "WebAuthn User",
		Password: "Zq8#Trn4$Vhx2@Wp!",
	})
	require.NoError(t, err)

	// Seed a passkey directly (bypassing the real attestation ceremony) so
	// BeginWebAuthnLogin has a registered credential to build assertion options
	// from — matching internal/core/webauthn_test.go's seedCredential helper.
	blob, err := json.Marshal(webauthn.Credential{ID: []byte("cred-1")})
	require.NoError(t, err)
	require.NoError(t, upstreamCore.Storage().CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
		UserID: waUser.ID, CredentialID: []byte("cred-1"), Name: "test key", CredentialBlob: blob,
	}))
	require.NoError(t, upstreamCore.Storage().SetUserWebAuthnEnabled(ctx, waUser.ID, true))

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
	downstreamCore.SetWebAuthn(rp)

	// Second-factor login issues the SAME shared MFAChallenge every second-factor
	// path uses (TOTP or WebAuthn), already proxied by #509's IssueMFAChallenge.
	challenge, err := downstreamCore.CreateMFAChallenge(ctx, waUser.ID)
	require.NoError(t, err)
	require.NotEmpty(t, challenge)

	// BeginWebAuthnLogin resolves the user from the challenge via
	// GetActiveMFAChallenge — the #522 fix. Before it, this failed immediately
	// with "operation not supported in remote (client) mode", making WebAuthn
	// login 100% broken under storage.type: remote.
	assertion, token, err := downstreamCore.BeginWebAuthnLogin(ctx, challenge)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, assertion.Response.Challenge)
	require.Len(t, assertion.Response.AllowedCredentials, 1, "the user's passkey is in allowCredentials")

	// Begin does NOT consume the challenge — GetActiveMFAChallenge is a peek, not
	// a consume, matching the local (non-remote) path's exact semantics
	// (internal/core/webauthn_test.go's TestWebAuthn_BeginLoginResolvesUserFromChallenge).
	// Calling it again must still succeed.
	assertion2, _, err := downstreamCore.BeginWebAuthnLogin(ctx, challenge)
	require.NoError(t, err, "the login challenge must stay valid until finish, matching the local path")
	require.NotEmpty(t, assertion2.Response.Challenge)

	// A bad/unknown challenge must fail through the proxy exactly like it does
	// locally.
	_, _, err = downstreamCore.BeginWebAuthnLogin(ctx, "not-a-real-challenge")
	require.Error(t, err)

	// ConsumeMFAChallenge (#522's other new route) atomically spends the
	// challenge in ONE round trip — the primitive FinishWebAuthnLogin calls
	// before verifying the assertion (a live, signed assertion is beyond this
	// proxy-focused test's scope; internal/core/webauthn_test.go already covers
	// the ceremony logic itself against LocalStorage).
	hash := mfaChallengeTokenHash(challenge)
	consumed, err := rs.ConsumeMFAChallenge(ctx, hash, time.Now())
	require.NoError(t, err)
	assert.Equal(t, waUser.ID, consumed.UserID)

	// Single-use: a second consume of the SAME challenge must fail — proving the
	// atomic "UPDATE ... WHERE used_at IS NULL" guarantee local_mfa.go's
	// ConsumeMFAChallenge already provides survives this HTTP hop too, not a
	// naive GET-then-mark-used pair that would reopen a concurrent-consume race.
	_, err = rs.ConsumeMFAChallenge(ctx, hash, time.Now())
	require.Error(t, err, "a challenge must be single-use even through the remote proxy")

	// GetActiveMFAChallenge must also now report the challenge as no longer active.
	_, err = rs.GetActiveMFAChallenge(ctx, hash, time.Now())
	require.Error(t, err, "a consumed challenge must not still read as active")

	// A challenge that never existed must fail the same way, not silently
	// succeed against some other row.
	_, err = rs.GetActiveMFAChallenge(ctx, mfaChallengeTokenHash("never-issued"), time.Now())
	require.Error(t, err)
}
