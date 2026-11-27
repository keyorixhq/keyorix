package main

// #4738 wiring guard: the client the OIDC code exchange runs on is the discovery
// client (same transport, same redirect policy), so the two cannot drift apart
// silently. The dial side is fuzzed by FuzzSSOExchangeTransportEgressParity; this
// test pins the transport identity and the redirect verdicts. It does not prove
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
		to  string
		via []*http.Request
	}{
		{"https://idp.example.com/b", via("https://idp.example.com/a")},
		{"https://idp.example.com:8443/b", via("https://idp.example.com/a")},
		{"http://127.0.0.1:2222/b", via("http://127.0.0.1:1111/a")},
		{"https://other.example.com/b", via("https://idp.example.com/a")},
		{"http://idp.example.com/b", via("https://idp.example.com/a")},
		{"http://169.254.169.254/latest", via("http://127.0.0.1:1111/token")},
		{"https://idp.example.com/c", via("https://idp.example.com/a", "https://idp.example.com/b")},
		{"https://idp.example.com/d", via("https://idp.example.com/a", "https://idp.example.com/b", "https://idp.example.com/c")},
	} {
		got := c.CheckRedirect(mk(tc.to), tc.via) == nil
		want := noDiscoveryCrossOriginRedirect(mk(tc.to), tc.via) == nil
		if got != want {
			t.Errorf("redirect to %s after %d hop(s): exchange allows=%v, discovery allows=%v", tc.to, len(tc.via), got, want)
		}
	}
	// The verdicts above only compare the two; pin the ones that matter so an
	// equally permissive pair is not green.
	if c.CheckRedirect(mk("http://127.0.0.1:2222/b"), via("http://127.0.0.1:1111/a")) == nil {
		t.Error("exchange client follows a redirect to another port of the same host")
	}
	if c.CheckRedirect(mk("http://169.254.169.254/latest"), via("http://127.0.0.1:1111/token")) == nil {
		t.Error("exchange client follows a redirect to the metadata address")
	}
}
