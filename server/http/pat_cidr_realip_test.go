package http

// pat_cidr_realip_test.go — independent verification for HARDENING-BACKLOG #302:
// does the same unconditional X-Forwarded-For trust that broke the login rate
// limiter (#301) also defeat the PAT IP/CIDR allowlist's documented guarantee
// (ADR-066, docs/adr-066-token-ip-allowlist.md:33-37 — "The source IP is the TCP
// peer (RemoteAddr), never a client-supplied header")?
//
// server/middleware/auth.go's tokenNetworkAllowed / clientIP read r.RemoteAddr,
// which by the time that code runs has already passed through the router's
// client-IP-resolution middleware (server/http/router.go). This test drives that
// full chain end-to-end with a real PAT carrying a configured CIDR allowlist and a
// spoofed X-Forwarded-For claiming an address inside the allowed range, to prove —
// not just assume — whether the control holds today.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// callWithPAT sends an authenticated GET to a PAT-protected endpoint with an
// optional spoofed X-Forwarded-For header and returns the response status code.
func callWithPAT(t *testing.T, client *http.Client, serverURL, patToken, xff string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, serverURL+"/api/v1/auth/profile", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+patToken)
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestPATCIDRAllowlist_DefaultConfig_RejectsSpoofedForwardedFor is the #302
// verification: with a PAT restricted to 203.0.113.0/24 and the DEFAULT config (no
// trusted proxies), a request whose real peer is 127.0.0.1 (outside the allowlist)
// but which sets X-Forwarded-For to an address INSIDE the allowlist must still be
// REJECTED — proving the ADR-066 control is not bypassable via a spoofed header now
// that #301's fix (server/middleware.ClientIP, wired in router.go) is in place.
func TestPATCIDRAllowlist_DefaultConfig_RejectsSpoofedForwardedFor(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := newTestCore(t)
	_ = createTestToken(t, c) // bootstraps the admin account (testadmin@example.com)
	ctx := context.Background()
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	patResult, err := c.CreateOwnPAT(ctx, admin.ID, "cidr-restricted", nil, nil, 0, 0, []string{"203.0.113.0/24"})
	require.NoError(t, err)
	patToken := patResult.PlainToken

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
			// No TrustedProxies configured — the fail-closed default.
		},
	}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()

	// Sanity: the token works from an address actually inside its allowlist. We
	// can't dial FROM 203.0.113.x in this test, so instead confirm the token is
	// otherwise valid by observing the deny is specifically network-based (403,
	// not 401) for the spoofed attempt below.
	status := callWithPAT(t, client, server.URL, patToken, "203.0.113.42")
	require.Equal(t, http.StatusForbidden, status,
		"a spoofed X-Forwarded-For claiming an in-allowlist address must NOT grant access "+
			"when the real peer (127.0.0.1, outside 203.0.113.0/24) is untrusted — "+
			"this is the concrete #302 proof-of-fix")

	// Without any header at all, the real peer (127.0.0.1) is also outside the
	// allowlist, so it's denied too — confirming the deny above was the network
	// check (not, say, an unrelated auth failure) and that RemoteAddr genuinely
	// drives the decision either way.
	status = callWithPAT(t, client, server.URL, patToken, "")
	require.Equal(t, http.StatusForbidden, status,
		"the real peer is outside the allowlist and must be denied with no header present")
}

// TestPATCIDRAllowlist_TrustedProxy_HonorsForwardedFor confirms the flip side: once
// the operator explicitly configures the loopback as a trusted proxy (simulating a
// real reverse-proxy deployment) AND the request's real peer is inside that trusted
// CIDR, the forwarded client IP is used for the allowlist check — so a PAT scoped to
// the real originating client's network is correctly honored, not just always denied.
func TestPATCIDRAllowlist_TrustedProxy_HonorsForwardedFor(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := newTestCore(t)
	_ = createTestToken(t, c)
	ctx := context.Background()
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	patResult, err := c.CreateOwnPAT(ctx, admin.ID, "cidr-restricted-2", nil, nil, 0, 0, []string{"203.0.113.0/24"})
	require.NoError(t, err)
	patToken := patResult.PlainToken

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{
				Enabled:        true,
				Port:           "8080",
				TrustedProxies: []string{"127.0.0.1/32"}, // the test client's real peer
			},
		},
	}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()

	// The peer (127.0.0.1) IS the trusted proxy, and it forwards a client IP inside
	// the token's allowlist → allowed.
	status := callWithPAT(t, client, server.URL, patToken, "203.0.113.42")
	require.Equal(t, http.StatusOK, status,
		"a forwarded client IP inside the allowlist, via a trusted proxy peer, must be honored")

	// Same trusted proxy, but forwarding a client IP OUTSIDE the allowlist → denied.
	status = callWithPAT(t, client, server.URL, patToken, "198.51.100.7")
	require.Equal(t, http.StatusForbidden, status,
		"a forwarded client IP outside the allowlist must still be denied even via a trusted proxy")
}
