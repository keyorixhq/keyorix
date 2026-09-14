// sso_pkce_test.go covers the PKCE (RFC 7636) hardening of the human OIDC
// authorization-code flow (F1, adversarial-review 2026-09-14): BeginSSO must send
// an S256 code_challenge derived from a verifier it persists with the login state,
// and CompleteSSO must replay that verifier on the token exchange (or omit it
// cleanly when a pre-PKCE state row carries none). The exchange assertion reads the
// value the token endpoint actually received — the effect — not a return value.
package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBeginSSO_IncludesPKCES256Challenge(t *testing.T) {
	t.Parallel()
	c, store, _, _ := ssoTestCore(t)
	var captured *models.SSOLoginState
	store.On("CreateSSOLoginState", mock.Anything, mock.MatchedBy(func(s *models.SSOLoginState) bool {
		captured = s
		return true
	})).Return(nil)

	raw, err := c.BeginSSO(context.Background(), "okta", "/secrets")
	require.NoError(t, err)
	require.NotNil(t, captured)
	require.NotEmpty(t, captured.CodeVerifier, "a PKCE verifier must be persisted with the login state")

	u, err := url.Parse(raw)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	challenge := q.Get("code_challenge")
	require.NotEmpty(t, challenge, "the auth URL must carry a code_challenge")

	// The challenge must be S256(verifier), base64url without padding.
	sum := sha256.Sum256([]byte(captured.CodeVerifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	assert.Equal(t, want, challenge, "code_challenge must be the S256 hash of the stored verifier")

	// The raw verifier must never travel to the browser in the IdP redirect.
	assert.NotContains(t, raw, captured.CodeVerifier, "the code_verifier must not leak into the IdP redirect URL")
}

func TestCompleteSSO_ReplaysPKCEVerifierOnExchange(t *testing.T) {
	t.Parallel()
	c, store, key, p := ssoTestCore(t)

	const testNonce = "nonce-pkce"
	const verifier = "pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	idToken := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://idp.test", "aud": "client-1", "sub": "okta|91",
		"email": "pkce@x.io", "email_verified": true, "nonce": testNonce,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	var gotVerifier string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotVerifier = r.Form.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)))
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	activeUser := &models.User{ID: 91, IsActive: true, AccountState: "active"}
	store.On("ConsumeSSOLoginState", mock.Anything, "state-pkce").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: testNonce, CodeVerifier: verifier, ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|91").Return(activeUser, nil)
	store.On("CreateSession", mock.Anything, mock.AnythingOfType("*models.Session")).
		Return(&models.Session{ID: 1, UserID: 91, SessionToken: "sess"}, nil)
	store.On("UpdateLastLogin", mock.Anything, uint(91), mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	_, _, _, err := c.CompleteSSO(context.Background(), "okta", "auth-code", "state-pkce", "ua", "1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, verifier, gotVerifier, "CompleteSSO must replay the stored PKCE verifier on the token exchange")
}

// TestCompleteSSO_OmitsVerifierForPrePKCEState covers the upgrade edge: a login
// state row created before PKCE existed carries no verifier, so CompleteSSO must
// NOT send an empty code_verifier (which some IdPs reject when no challenge was
// sent) — it must complete exactly as the pre-PKCE flow did.
func TestCompleteSSO_OmitsVerifierForPrePKCEState(t *testing.T) {
	t.Parallel()
	c, store, key, p := ssoTestCore(t)

	const testNonce = "nonce-no-pkce"
	idToken := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://idp.test", "aud": "client-1", "sub": "okta|92",
		"email": "nopkce@x.io", "email_verified": true, "nonce": testNonce,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	sawVerifierField := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, sawVerifierField = r.Form["code_verifier"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)))
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	activeUser := &models.User{ID: 92, IsActive: true, AccountState: "active"}
	store.On("ConsumeSSOLoginState", mock.Anything, "state-no-pkce").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: testNonce, CodeVerifier: "", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|92").Return(activeUser, nil)
	store.On("CreateSession", mock.Anything, mock.AnythingOfType("*models.Session")).
		Return(&models.Session{ID: 1, UserID: 92, SessionToken: "sess"}, nil)
	store.On("UpdateLastLogin", mock.Anything, uint(92), mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	_, _, _, err := c.CompleteSSO(context.Background(), "okta", "auth-code", "state-no-pkce", "ua", "1.2.3.4")
	require.NoError(t, err)
	assert.False(t, sawVerifierField, "an empty verifier must be omitted entirely, not sent as code_verifier=")
}
