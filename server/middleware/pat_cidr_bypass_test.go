package middleware

// pat_cidr_bypass_test.go — HARDENING-BACKLOG #302 mechanism proof: it demonstrates
// that the router's PRE-fix wiring — chi's stock, unconditional middleware.RealIP
// ahead of Authentication — would have let a spoofed X-Forwarded-For defeat a PAT's
// ADR-066 CIDR allowlist, and contrasts it with the current ClientIP(trustedProxies)
// middleware (server/middleware/client_ip.go), which this repo actually uses
// (wired in server/http/router.go) and which closes the gap by default.
//
// "kx_pat_cidrtoken" (fakeValidator, auth_test.go) is restricted to 10.0.0.0/8.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
)

// serveWithChain runs a request through the given outer middleware (simulating the
// router's client-IP-resolution stage) followed by the real Authentication
// middleware, and returns the response status.
func serveWithChain(clientIPMW func(http.Handler) http.Handler, remoteAddr string, headers map[string]string) int {
	auth := newTestAuthMiddleware()
	final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := clientIPMW(auth(final))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer kx_pat_cidrtoken")
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}

// TestPATCIDRAllowlist_UnconditionalRealIP_WasBypassable is the "before" half of the
// #302 verification: chi's stock middleware.RealIP (what this router used before the
// #301 fix) blindly copies X-Forwarded-For into r.RemoteAddr for ANY caller, with no
// trusted-hop check. Run in front of the real Authentication middleware, a request
// whose actual peer (203.0.113.9, off-network) spoofs X-Forwarded-For to an
// in-allowlist address (10.1.2.3) is INCORRECTLY authorized — concretely proving the
// backlog's "very likely" claim for #302 was correct.
func TestPATCIDRAllowlist_UnconditionalRealIP_WasBypassable(t *testing.T) {
	status := serveWithChain(chimw.RealIP, "203.0.113.9:5555", map[string]string{
		"X-Forwarded-For": "10.1.2.3",
	})
	assert.Equal(t, http.StatusOK, status,
		"BEFORE fix: unconditional RealIP trusts the spoofed header, incorrectly bypassing the PAT's "+
			"10.0.0.0/8 allowlist for an off-network caller — this is the #302 vulnerability mechanism")
}

// TestPATCIDRAllowlist_ClientIPMiddleware_RejectsSpoofedHeader is the "after" half:
// this repo's actual ClientIP middleware, with no trusted proxies configured (the
// fail-closed default), ignores the same spoofed header and keeps the real peer, so
// the off-network caller is correctly denied.
func TestPATCIDRAllowlist_ClientIPMiddleware_RejectsSpoofedHeader(t *testing.T) {
	status := serveWithChain(ClientIP(nil), "203.0.113.9:5555", map[string]string{
		"X-Forwarded-For": "10.1.2.3",
	})
	assert.Equal(t, http.StatusForbidden, status,
		"AFTER fix: with no trusted proxies configured, the spoofed header must be ignored and the "+
			"off-network peer denied by the PAT's CIDR allowlist")
}

// TestPATCIDRAllowlist_ClientIPMiddleware_HonorsTrustedProxy confirms the fix does
// not just always deny: when the peer genuinely IS a configured trusted proxy, the
// forwarded (in-allowlist) client IP is honored and access is correctly granted.
func TestPATCIDRAllowlist_ClientIPMiddleware_HonorsTrustedProxy(t *testing.T) {
	status := serveWithChain(ClientIP([]string{"203.0.113.0/24"}), "203.0.113.9:5555", map[string]string{
		"X-Forwarded-For": "10.1.2.3",
	})
	assert.Equal(t, http.StatusOK, status,
		"a forwarded in-allowlist client IP via a genuinely trusted proxy peer must be honored")
}
