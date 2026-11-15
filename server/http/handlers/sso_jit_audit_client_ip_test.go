// sso_jit_audit_client_ip_test.go — SSO-AUDIT-TAILS-NOV-1 item 1: the
// auth.sso_jit_provisioned event written by a login that creates the account
// names the client the login came from, as the auth.sso_login event does
// (sso_login_audit_client_ip_test.go). Behind a trusted proxy that is the
// forwarded client, never the proxy's RemoteAddr and never nothing.
//
// RED before the fix: the JIT event was written with an empty IP. The reconcile
// events (auth.sso_groups_synced and friends) take the same `ip` through
// internal/core and are pinned there (sso_account_events_client_ip_test.go).
package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

func TestCompleteSAML_JITProvisionAuditRecordsTheForwardedClientBehindTrustedProxy(t *testing.T) {
	_, db := samlBehindProxyLogin(t)
	assert.Equal(t, ssoAuditForwardedFor, lastAuditIP(t, db, core.EventSSOJITProvision),
		"the JIT-provision event must name the client behind the trusted proxy, not the proxy and not nothing")
}

func TestCompleteSSO_JITProvisionAuditRecordsTheForwardedClientBehindTrustedProxy(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	seedSSODefaultRoleS13(t, cs)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &core.SSOProvider{
		Name: "oidcjit", Issuer: "https://idp.test.example", ClientID: "cid",
		CompleteURL: "https://app.example.com/sso/complete", AutoProvision: true,
		OAuth: &oauth2.Config{
			ClientID:    "cid",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test.example/authorize"},
			RedirectURL: "https://app.example.com/auth/sso/oidcjit/callback",
		},
	}
	cs.SetSSOProviders(map[string]*core.SSOProvider{"oidcjit": p}, staticJWKSResolver{key: &key.PublicKey})
	h := NewAuthHandler(cs, false)
	require.NoError(t, db.Create(&models.SSOLoginState{
		State: "state-jit", Nonce: "nonce-jit", Provider: "oidcjit",
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}).Error)
	idToken := signSSOToken(t, key, jwt.MapClaims{
		"iss": p.Issuer, "aud": "cid", "sub": "sub-jit", "email": "jit-oidc@example.com",
		"email_verified": true, "nonce": "nonce-jit", "exp": time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	req := withChiParam(httptest.NewRequest(http.MethodGet,
		"/auth/sso/oidcjit/callback?code=c&state="+url.QueryEscape("state-jit"), nil), "provider", "oidcjit")
	req.RemoteAddr = ssoAuditTrustedProxy
	req.Header.Set("X-Forwarded-For", ssoAuditForwardedFor)
	w := httptest.NewRecorder()
	customMiddleware.ClientIP([]string{"10.0.0.0/8"})(http.HandlerFunc(h.CompleteSSO)).ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	require.NotContains(t, w.Header().Get("Location"), "error=")
	assert.Equal(t, ssoAuditForwardedFor, lastSessionIP(t, db), "calibration: the session records the forwarded client")
	assert.Equal(t, ssoAuditForwardedFor, lastAuditIP(t, db, core.EventSSOJITProvision),
		"the OIDC JIT-provision event must name the client behind the trusted proxy")
}
