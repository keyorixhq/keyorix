// webauthn_rp_test.go covers the WebAuthn hardening assertions from the
// 2026-09-14 adversarial review (F5). The origin/RP-ID match and the actual
// signature/UV cryptographic checks live inside the (un-vendored) go-webauthn
// library; rather than reconstruct a full software-authenticator ceremony, these
// tests assert the CONDITIONS keyorix controls that make the library enforce the
// properties (CLAUDE.md: "guard the condition, not the conclusion"):
//   - every begin-ceremony path requests UserVerification=required, so the library
//     rejects a UV=false assertion;
//   - a user's login ceremony only ever offers that user's own credentials, so a
//     credential belonging to another user can never be presented into it.
package core

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebAuthn_BeginCeremoniesRequireUserVerification asserts that all three
// server-initiated assertion ceremonies (2FA login, passwordless login, step-up
// reauth) request UV=required. A regression that dropped this to preferred/
// discouraged would let a stolen/found hardware key satisfy authentication with
// no PIN/biometric — the library only enforces UV when we ask for it.
func TestWebAuthn_BeginCeremoniesRequireUserVerification(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	loginAssertion, _, err := c.BeginWebAuthnLogin(ctx, ch)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationRequired, loginAssertion.Response.UserVerification,
		"2FA login must request user verification")

	pwlAssertion, _, err := c.BeginWebAuthnPasswordlessLogin(ctx)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationRequired, pwlAssertion.Response.UserVerification,
		"passwordless login must request user verification")

	reauthAssertion, _, err := c.BeginWebAuthnReauth(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, protocol.VerificationRequired, reauthAssertion.Response.UserVerification,
		"step-up reauth must request user verification")
}

// TestWebAuthn_LoginCeremonyOffersOnlyOwnCredentials is the credential-ownership
// seam: a login ceremony for user A must offer only user A's passkeys, so a
// credential registered to user B can never be presented into A's challenge. It
// asserts both the loadWebAuthnUser boundary and the allowCredentials list the
// ceremony actually emits.
func TestWebAuthn_LoginCeremonyOffersOnlyOwnCredentials(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()

	// User 1 (alice, seeded by the fixture) has cred-A; user 2 (bob) has cred-B.
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", AccountState: "active"}).Error)
	seedCredential(t, c, db, 1, "cred-A")
	seedCredential(t, c, db, 2, "cred-B")

	wu, err := c.loadWebAuthnUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, wu.creds, 1, "user 1 must load exactly their own credential")
	assert.Equal(t, []byte("cred-A"), wu.creds[0].ID, "user 1 must not see another user's credential")

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	assertion, _, err := c.BeginWebAuthnLogin(ctx, ch)
	require.NoError(t, err)
	require.Len(t, assertion.Response.AllowedCredentials, 1, "only user 1's own passkey may be offered")
	assert.Equal(t, []byte("cred-A"), []byte(assertion.Response.AllowedCredentials[0].CredentialID),
		"a credential belonging to another user must never appear in this user's allowCredentials")
}
