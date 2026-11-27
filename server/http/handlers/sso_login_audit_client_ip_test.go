// sso_login_audit_client_ip_test.go — #2934 item (b), the audit and budget half
// (SAML-TAILS-1 item 1). sso_session_client_ip_test.go and
// sso_session_trusted_proxy_ip_test.go pin that an SSO session records
// clientIP(r), the address the production ClientIP middleware resolved
// (trusted-proxy aware). These pin the two other places the same login puts a
// client address: the auth.sso_login audit event, and the per-IP SSO budget
// key (BeginSAML's sso_begin budget; the ACS itself is budget-exempt,
// auth_budget_routes_guard_test.go).
//
// RED on main before the fix: auth.sso_login was written through
// writeAuditEvent, which passes an empty IP, so the event carried no address at
// all while the session it announced carried the forwarded client's.
package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

const (
	ssoAuditTrustedProxy = "10.1.2.3:44444"
	ssoAuditForwardedFor = "198.51.100.9"
)

func lastAuditIP(t *testing.T, db *gorm.DB, eventType string) string {
	t.Helper()
	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", eventType).Order("id desc").First(&ev).Error,
		"a successful SSO login must have written %s", eventType)
	return ev.IPAddress
}

func TestCompleteSAML_LoginAuditRecordsTheSessionsClientIPBehindTrustedProxy(t *testing.T) {
	_, db := samlBehindProxyLogin(t)
	assert.Equal(t, ssoAuditForwardedFor, lastSessionIP(t, db), "calibration: the session records the forwarded client")
	assert.Equal(t, ssoAuditForwardedFor, lastAuditIP(t, db, core.EventSSOLogin),
		"the login audit event must name the same client the session records, not the proxy and not nothing")
}

func samlBehindProxyLogin(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	stub := &stubAssertionSAML{info: &samlpkg.AssertionInfo{Subject: "sub-audit-ip", Email: "audit-ip-saml@example.com", Name: "AIP"}}
	cs, db := freshCoreS12WithAdmin(t)
	seedSSODefaultRoleS13(t, cs)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {Name: "corp", Type: "saml", SAML: stub, CompleteURL: "https://app.example/auth/sso/complete", AutoProvision: true},
	}, nil)
	h := NewAuthHandler(cs, false)
	require.NoError(t, db.Create(&models.SSOLoginState{
		State: "relay-aip", Nonce: "nonce-aip", Provider: "corp",
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}).Error)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs",
		strings.NewReader("RelayState=relay-aip&SAMLResponse=stub")), "provider", "corp")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ssoAuditTrustedProxy
	req.Header.Set("X-Forwarded-For", ssoAuditForwardedFor)
	w := httptest.NewRecorder()
	customMiddleware.ClientIP([]string{"10.0.0.0/8"})(http.HandlerFunc(h.CompleteSAML)).ServeHTTP(w, req)
	require.Equal(t, http.StatusFound, w.Code)
	require.NotContains(t, w.Header().Get("Location"), "error=")
	return cs, db
}

// The OIDC callback is the sibling call site in internal/core/sso.go and had
// the same empty-IP audit write.
func TestCompleteSSO_LoginAuditRecordsTheSessionsClientIPBehindTrustedProxy(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &core.SSOProvider{
		Name: "oidcaip", Issuer: "https://idp.test.example", ClientID: "cid",
		CompleteURL: "https://app.example.com/sso/complete",
		HTTPClient:  &http.Client{},
		OAuth: &oauth2.Config{
			ClientID:    "cid",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test.example/authorize"},
			RedirectURL: "https://app.example.com/auth/sso/oidcaip/callback",
		},
	}
	cs.SetSSOProviders(map[string]*core.SSOProvider{"oidcaip": p}, staticJWKSResolver{key: &key.PublicKey})
	h := NewAuthHandler(cs, false)
	_, err = cs.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "aipuser", Email: "aip-oidc@x.io", DisplayName: "AIP", Password: "pw-Aa1!aaaa-longenough",
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.SSOLoginState{
		State: "state-aip", Nonce: "nonce-aip", Provider: "oidcaip",
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}).Error)
	idToken := signSSOToken(t, key, jwt.MapClaims{
		"iss": p.Issuer, "aud": "cid", "sub": "sub-aip", "email": "aip-oidc@x.io",
		"email_verified": true, "nonce": "nonce-aip", "exp": time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	req := withChiParam(httptest.NewRequest(http.MethodGet,
		"/auth/sso/oidcaip/callback?code=c&state="+url.QueryEscape("state-aip"), nil), "provider", "oidcaip")
	req.RemoteAddr = ssoAuditTrustedProxy
	req.Header.Set("X-Forwarded-For", ssoAuditForwardedFor)
	w := httptest.NewRecorder()
	customMiddleware.ClientIP([]string{"10.0.0.0/8"})(http.HandlerFunc(h.CompleteSSO)).ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	require.NotContains(t, w.Header().Get("Location"), "error=")
	assert.Equal(t, ssoAuditForwardedFor, lastSessionIP(t, db), "calibration: the session records the forwarded client")
	assert.Equal(t, ssoAuditForwardedFor, lastAuditIP(t, db, core.EventSSOLogin),
		"the login audit event must name the same client the session records")
}

// The SAML login's per-IP budget (sso_begin, spent on BeginSAML) is keyed by the
// same resolved client address: two clients behind one trusted proxy have
// separate budgets, so one exhausting its budget does not lock the other out,
// and the exhausted one is refused even though the TCP peer is shared.
// Regression pin: green on main (BeginSAML already used clientIP(r)).
func TestBeginSAML_BudgetKeyIsTheForwardedClientBehindTrustedProxy(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	chain := customMiddleware.ClientIP([]string{"10.0.0.0/8"})(http.HandlerFunc(h.BeginSAML))
	begin := func(forwardedFor string) int {
		req := withChiParam(httptest.NewRequest(http.MethodGet, "/auth/saml/none/login", nil), "provider", "none")
		req.RemoteAddr = ssoAuditTrustedProxy
		req.Header.Set("X-Forwarded-For", forwardedFor)
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, req)
		return w.Code
	}
	for i := range core.SSOBeginMaxAttempts {
		require.NotEqual(t, http.StatusTooManyRequests, begin(ssoAuditForwardedFor), "attempt %d is inside the budget", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, begin(ssoAuditForwardedFor),
		"the forwarded client that spent its budget is refused")
	assert.NotEqual(t, http.StatusTooManyRequests, begin("198.51.100.10"),
		"a second client behind the same proxy has its own budget: the key is the forwarded client, not the proxy")
}
