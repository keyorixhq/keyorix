package main

// #4738: the OIDC authorization-code exchange is the one SSO request whose
// destination comes from a third-party response (the discovery document's
// token_endpoint), and it carries the provider's client credentials and the
// one-time code. These tests drive the real wiring end to end: a fake IdP serves
// discovery, buildSSOProviders builds the provider from it exactly as boot does,
// BeginSSO stores the login state, and CompleteSSO runs the exchange the
// /auth/sso/{provider}/callback handler runs. "Internal" is a second loopback
// listener that stands in for an internal or metadata service: the assertions are
// on what it received (the effect), not on CompleteSSO's return value, because the
// handler masks that error from the browser anyway.
//
// Not verified here: a dial to a link-local address (no test can listen on
// 169.254.0.0/16; the exchange client's dial guard is covered by
// FuzzSSOExchangeTransportEgressParity), an https token_endpoint (the fake IdP is
// http on loopback, the dev shape the discovery rule permits), and the
// session-minting steps after the exchange (the controls stop at the first step
// after a successful exchange).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	ssoExchangeClientSecret = "kx-4738-client-secret-canary"
	ssoExchangeCode         = "kx-4738-code-canary"
)

// ssoExchangeSink records every request a listener receives, with its body.
type ssoExchangeSink struct {
	mu     sync.Mutex
	bodies []string
}

func (s *ssoExchangeSink) record(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies = append(s.bodies, r.Method+" "+r.URL.Path+" "+string(b)+" auth="+r.Header.Get("Authorization"))
}

func (s *ssoExchangeSink) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.bodies...)
}

// newSSOExchangeInternal is the stand-in internal service. It answers like a
// token endpoint so that, if it is reached, the exchange "succeeds" and nothing
// hides the fact that the credentials were delivered.
func newSSOExchangeInternal(t *testing.T, host string) (*httptest.Server, *ssoExchangeSink, string) {
	t.Helper()
	sink := &ssoExchangeSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sink.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return srv, sink, "http://" + host + ":" + u.Port()
}

// newSSOExchangeIdP serves a discovery document whose token_endpoint is
// tokenEndpoint(issuer) and routes /token to tokenHandler.
func newSSOExchangeIdP(t testing.TB, tokenEndpoint func(issuer string) string, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         tokenEndpoint(srv.URL),
				"jwks_uri":               srv.URL + "/jwks",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			if tokenHandler != nil {
				tokenHandler(w, r)
				return
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runSSOExchange wires the IdP through buildSSOProviders and runs BeginSSO +
// CompleteSSO. built reports whether discovery accepted the provider; when it did
// not, no exchange runs and err is nil.
func runSSOExchange(t *testing.T, issuer string) (built bool, err error) {
	t.Helper()
	providers, jwks, n := buildSSOProviders(config.SSOConfig{
		Enabled: true,
		Providers: []config.SSOProviderConfig{{
			Name: "kx4738", Issuer: issuer, ClientID: "kx-4738-client",
			ClientSecret: ssoExchangeClientSecret,
			RedirectURL:  "https://keyorix.test/auth/sso/kx4738/callback",
		}},
	})
	if n == 0 {
		return false, nil
	}
	db, oerr := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "sso.db")), &gorm.Config{})
	if oerr != nil {
		t.Fatalf("open db: %v", oerr)
	}
	if merr := db.AutoMigrate(&models.SSOLoginState{}); merr != nil {
		t.Fatalf("migrate: %v", merr)
	}
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetSSOProviders(providers, jwks)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	authURL, berr := c.BeginSSO(ctx, "kx4738", "")
	if berr != nil {
		t.Fatalf("BeginSSO: %v", berr)
	}
	u, perr := url.Parse(authURL)
	if perr != nil {
		t.Fatalf("parse auth URL: %v", perr)
	}
	_, _, _, err = c.CompleteSSO(ctx, "kx4738", ssoExchangeCode, u.Query().Get("state"), "ua", "203.0.113.9")
	return true, err
}

func assertNothingDelivered(t *testing.T, sink *ssoExchangeSink) {
	t.Helper()
	for _, req := range sink.seen() {
		t.Errorf("internal listener received the exchange: %s", req)
	}
}

// TestSSOTokenEndpointOffIssuerHostNeverReceivesExchange: a discovery document
// that names a token_endpoint on a host other than the issuer's (here localhost
// for an issuer on 127.0.0.1, the same shape as a compromised IdP naming an
// internal address) must not receive the client secret and code.
func TestSSOTokenEndpointOffIssuerHostNeverReceivesExchange(t *testing.T) {
	_, sink, internalBase := newSSOExchangeInternal(t, "localhost")
	idp := newSSOExchangeIdP(t, func(string) string { return internalBase + "/token" }, nil)

	built, err := runSSOExchange(t, idp.URL)
	assertNothingDelivered(t, sink)
	if built {
		t.Errorf("discovery accepted a token_endpoint off the issuer host (exchange err: %v)", err)
	}
}

// TestSSOTokenExchangeCrossOriginRedirectNotFollowed: the token_endpoint is on
// the issuer's own origin, but it answers the POST with a 307 (which keeps the
// method and body) to another origin. The exchange must not follow it.
func TestSSOTokenExchangeCrossOriginRedirectNotFollowed(t *testing.T) {
	_, sink, internalBase := newSSOExchangeInternal(t, "127.0.0.1")
	idp := newSSOExchangeIdP(t,
		func(issuer string) string { return issuer + "/token" },
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internalBase+"/latest/meta-data", http.StatusTemporaryRedirect)
		})

	built, err := runSSOExchange(t, idp.URL)
	if !built {
		t.Fatal("discovery refused a same-origin token_endpoint; the redirect was never exercised")
	}
	assertNothingDelivered(t, sink)
	if err == nil {
		t.Error("the exchange succeeded through a cross-origin redirect")
	}
}

// TestSSOTokenExchangeSameOriginControl is the green control: a token_endpoint on
// the issuer's origin, reached directly and through one same-origin 307, still
// exchanges the code. The exchange is shown to succeed by CompleteSSO failing at
// the next step (the response carried no id_token), and by the endpoint having
// received the code and the client credentials.
func TestSSOTokenExchangeSameOriginControl(t *testing.T) {
	for _, tc := range []struct {
		name     string
		redirect bool
	}{{"direct", false}, {"same-origin 307", true}} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &ssoExchangeSink{}
			idp := newSSOExchangeIdP(t,
				func(issuer string) string { return issuer + "/token" },
				func(w http.ResponseWriter, r *http.Request) {
					if tc.redirect && r.URL.Path == "/token" {
						http.Redirect(w, r, "/token2", http.StatusTemporaryRedirect)
						return
					}
					sink.record(r)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
				})

			built, err := runSSOExchange(t, idp.URL)
			if !built {
				t.Fatal("discovery refused a same-origin token_endpoint")
			}
			if err == nil || !strings.Contains(err.Error(), "the token response carried no id_token") {
				t.Fatalf("want the post-exchange id_token error, got %v", err)
			}
			seen := sink.seen()
			if len(seen) == 0 || !strings.Contains(seen[0], "code="+ssoExchangeCode) {
				t.Fatalf("token endpoint did not receive the code: %q", seen)
			}
		})
	}
}
