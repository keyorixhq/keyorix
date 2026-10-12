// sso_session_client_ip_test.go — found by the #2910 fault sweep. The SAML ACS
// and OIDC callback handlers passed the raw r.RemoteAddr ("ip:port") to core as
// the new session's IP, while every other login path passes clientIP(r), the
// canonical IP without the per-connection ephemeral port. So every SSO
// session recorded a port that changes on every reconnect, and two SSO
// sessions from the same client never had the same IP. The fuzzer saw it as
// a fault world whose Session row could never match the reference world's.
package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
)

const ssoClientIPRemoteAddr = "203.0.113.7:51234"

func lastSessionIP(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var s models.Session
	require.NoError(t, db.Order("id desc").First(&s).Error, "a successful SSO login must have created a session")
	return s.IPAddress
}

// RED before the fix: IPAddress was "203.0.113.7:51234".
func TestCompleteSAML_SessionRecordsCanonicalClientIP(t *testing.T) {
	stub := &stubAssertionSAML{info: &samlpkg.AssertionInfo{Subject: "sub-ip", Email: "ip-saml@example.com", Name: "IP"}}
	cs, db := freshCoreS12WithAdmin(t)
	seedSSODefaultRoleS13(t, cs)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {Name: "corp", Type: "saml", SAML: stub, CompleteURL: "https://app.example/auth/sso/complete", AutoProvision: true},
	}, nil)
	h := NewAuthHandler(cs, false)
	require.NoError(t, db.Create(&models.SSOLoginState{
		State: "relay-ip", Nonce: "nonce-ip", Provider: "corp",
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}).Error)

	req := withChiParam(httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs",
		strings.NewReader("RelayState=relay-ip&SAMLResponse=stub")), "provider", "corp")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ssoClientIPRemoteAddr
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	require.NotContains(t, w.Header().Get("Location"), "error=")
	assert.Equal(t, "203.0.113.7", lastSessionIP(t, db))
}

// RED before the fix: IPAddress was "203.0.113.7:51234".
func TestCompleteSSO_SessionRecordsCanonicalClientIP(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &core.SSOProvider{
		Name: "oidcip", Issuer: "https://idp.test.example", ClientID: "cid",
		CompleteURL: "https://app.example.com/sso/complete",
		OAuth: &oauth2.Config{
			ClientID:    "cid",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test.example/authorize"},
			RedirectURL: "https://app.example.com/auth/sso/oidcip/callback",
		},
	}
	cs.SetSSOProviders(map[string]*core.SSOProvider{"oidcip": p}, staticJWKSResolver{key: &key.PublicKey})
	h := NewAuthHandler(cs, false)
	_, err = cs.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "ipuser", Email: "ip-oidc@x.io", DisplayName: "IP", Password: "pw-Aa1!aaaa-longenough",
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.SSOLoginState{
		State: "state-ip", Nonce: "nonce-ip", Provider: "oidcip",
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}).Error)
	idToken := signSSOToken(t, key, jwt.MapClaims{
		"iss": p.Issuer, "aud": "cid", "sub": "sub-ip", "email": "ip-oidc@x.io",
		"email_verified": true, "nonce": "nonce-ip", "exp": time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	req := withChiParam(httptest.NewRequest(http.MethodGet,
		"/auth/sso/oidcip/callback?code=c&state="+url.QueryEscape("state-ip"), nil), "provider", "oidcip")
	req.RemoteAddr = ssoClientIPRemoteAddr
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	require.NotContains(t, w.Header().Get("Location"), "error=")
	assert.Equal(t, "203.0.113.7", lastSessionIP(t, db))
}

// TestLoginHandlers_NeverPassRawRemoteAddrToALoginCall is the guard for the
// CLASS. No call in this package to a core method that mints a session may
// take r.RemoteAddr as an argument. clientIP(r) is the one canonicalisation
// point. The set of session-minting core methods is the ones this file names
// (sessionMintingCoreMethods). How it was established: grepping
// internal/core for callers of mintSession (Login, CompleteSSO, CompleteSAML,
// FinishWebAuthnLogin, FinishWebAuthnPasswordlessLogin, VerifyMFALogin,
// ConsumeSetup). What it does NOT cover: a NEW session-minting method nobody
// adds here. Audit-only call sites that pass r.RemoteAddr (folders,
// secrets_*) are not login calls and are out of scope.
func TestLoginHandlers_NeverPassRawRemoteAddrToALoginCall(t *testing.T) {
	sessionMintingCoreMethods := map[string]bool{
		"Login": true, "CompleteSSO": true, "CompleteSAML": true,
		"FinishWebAuthnLogin": true, "FinishWebAuthnPasswordlessLogin": true,
		"VerifyMFALogin": true, "ConsumeSetup": true,
	}
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		file, err := parser.ParseFile(fset, f, src, 0)
		require.NoError(t, err)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !sessionMintingCoreMethods[sel.Sel.Name] {
				return true
			}
			checked++
			for _, arg := range call.Args {
				if a, ok := arg.(*ast.SelectorExpr); ok && a.Sel.Name == "RemoteAddr" {
					t.Errorf("%s: %s(...) is passed %s raw; pass clientIP(r) so the session records the canonical IP, not ip:port",
						fset.Position(call.Pos()), sel.Sel.Name, "r.RemoteAddr")
				}
			}
			return true
		})
	}
	// Green-but-vacuous check: the scan must have seen the two SSO call sites.
	require.GreaterOrEqual(t, checked, 2, "found no session-minting calls at all -- the scan is not looking where the code is")
}
