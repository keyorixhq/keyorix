package main

// #4738 wiring guard: the client the OIDC code exchange runs on is the discovery
// client (same transport, same redirect policy), so the two cannot drift apart
// silently. The dial side is fuzzed by FuzzSSOExchangeTransportEgressParity; this
// test pins the transport identity and the redirect verdicts (explicit, not
// compared with the discovery function, which is the same function). It does not prove
// that CompleteSSO uses the client (sso_exchange_egress_test.go does, by effect).

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// buildSSOExchangeTestProvider builds one OIDC provider through buildSSOProviders
// from a fake loopback IdP, exactly as boot does.
func buildSSOExchangeTestProvider(tb testing.TB) *core.SSOProvider {
	tb.Helper()
	idp := newSSOExchangeIdP(tb, func(issuer string) string { return issuer + "/token" }, nil)
	providers, _, n := buildSSOProviders(config.SSOConfig{
		Enabled: true,
		Providers: []config.SSOProviderConfig{{
			Name: "kx4738", Issuer: idp.URL, ClientID: "kx-4738-client",
			RedirectURL: "https://keyorix.test/auth/sso/kx4738/callback",
		}},
	})
	if n != 1 || providers["kx4738"] == nil {
		tb.Fatalf("buildSSOProviders built %d providers, want the fake IdP's", n)
	}
	p := providers["kx4738"]
	if p.HTTPClient == nil {
		tb.Fatal("buildSSOProviders left the exchange client nil")
	}
	return p
}

func TestSSOExchangeClientIsTheDiscoveryClient(t *testing.T) {
	c := buildSSOExchangeTestProvider(t).HTTPClient
	if c.Transport != oidcDiscoveryTransport {
		t.Errorf("exchange transport is %T %p, want oidcDiscoveryTransport %p", c.Transport, c.Transport, oidcDiscoveryTransport)
	}
	if c.Timeout <= 0 {
		t.Error("exchange client has no timeout")
	}
	if c.CheckRedirect == nil {
		t.Fatal("exchange client follows Go's default redirect policy")
	}
	mk := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	via := func(raws ...string) []*http.Request {
		out := make([]*http.Request, 0, len(raws))
		for _, r := range raws {
			out = append(out, mk(r))
		}
		return out
	}
	for _, tc := range []struct {
		to    string
		via   []*http.Request
		allow bool
	}{
		{"https://idp.example.com/b", via("https://idp.example.com/a"), true},
		{"https://IDP.example.com/b", via("https://idp.example.com/a"), true},
		{"https://idp.example.com:8443/b", via("https://idp.example.com/a"), false},
		{"http://127.0.0.1:2222/b", via("http://127.0.0.1:1111/a"), false},
		{"https://other.example.com/b", via("https://idp.example.com/a"), false},
		{"http://idp.example.com/b", via("https://idp.example.com/a"), false},
		{"http://169.254.169.254/latest", via("http://127.0.0.1:1111/token"), false},
		{"https://idp.example.com/c", via("https://idp.example.com/a", "https://idp.example.com/b"), true},
		{"https://idp.example.com/d", via("https://idp.example.com/a", "https://idp.example.com/b", "https://idp.example.com/c"), false},
	} {
		if got := c.CheckRedirect(mk(tc.to), tc.via) == nil; got != tc.allow {
			t.Errorf("redirect to %s after %d request(s): allowed=%v, want %v", tc.to, len(tc.via), got, tc.allow)
		}
	}
}

// TestValidateTokenEndpoint covers the discovery-time rule, including the
// operator-listed hosts the end-to-end tests do not configure.
func TestValidateTokenEndpoint(t *testing.T) {
	httpsIss, _ := url.Parse("https://iss.example")
	httpIss, _ := url.Parse("http://127.0.0.1:9")
	for _, tc := range []struct {
		name  string
		iss   *url.URL
		tok   string
		list  []string
		allow bool
	}{
		{"issuer host", httpsIss, "https://iss.example/token", nil, true},
		{"issuer host, other port", httpsIss, "https://ISS.example:8443/token", nil, true},
		{"other host, unlisted", httpsIss, "https://tok.example/t", nil, false},
		{"listed host", httpsIss, "https://tok.example/t", []string{"tok.example"}, true},
		{"listed host, padded entry", httpsIss, "https://tok.example/t", []string{" tok.example "}, true},
		{"listed host over http", httpsIss, "http://tok.example/t", []string{"tok.example"}, false},
		{"https issuer, http loopback endpoint", httpsIss, "http://127.0.0.1/t", []string{"127.0.0.1"}, false},
		{"http loopback issuer, http same host", httpIss, "http://127.0.0.1:10/t", nil, true},
		{"http loopback issuer, http metadata", httpIss, "http://169.254.169.254/t", []string{"169.254.169.254"}, false},
		{"userinfo trick", httpsIss, "https://iss.example@evil.example/t", nil, false},
		{"empty hostname vs empty entry", httpsIss, "https://:443/t", []string{""}, false},
		{"opaque", httpsIss, "https:iss.example", nil, false},
		{"scheme", httpsIss, "ftp://iss.example/t", nil, false},
		{"listed URL never matches", httpsIss, "https://tok.example/t", []string{"https://tok.example"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenEndpoint(tc.tok, tc.iss, tc.list)
			if (err == nil) != tc.allow {
				t.Fatalf("validateTokenEndpoint(%q, %v) = %v, want allowed=%v", tc.tok, tc.list, err, tc.allow)
			}
		})
	}
}
