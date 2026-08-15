// g20_client_ip_test.go — #G20 regression test: clientIP (admin_impersonation.go)
// used a naive strings.LastIndex(":")-based port strip that didn't account for
// IPv6 at all — a bracketed "[::1]:8080" kept its brackets (a different string
// than the canonical "::1"), and a bare, already-port-free IPv6 address had its
// LAST colon truncated as if it were a port separator, corrupting the address
// entirely. clientIP now delegates to core.CanonicalIP.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientIP_CanonicalizesEveryForm(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"IPv4 with port", "203.0.113.9:5555", "203.0.113.9"},
		{"bracketed IPv6 with port", "[2001:db8::1]:5555", "2001:db8::1"},
		{"bare unbracketed IPv6, no port", "2001:db8::1", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			assert.Equal(t, tc.want, clientIP(r))
		})
	}
}
