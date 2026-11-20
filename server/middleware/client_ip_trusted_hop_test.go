package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestParseCIDRs_IPv4MappedBareEntryIsSingleHost pins #4520 part 1: a bare trusted
// proxy written as an IPv4-mapped IPv6 address must cover exactly that IPv4 host,
// not the IPv6 network ::/32 (which contains ::1 and every other ::/32 peer).
func TestParseCIDRs_IPv4MappedBareEntryIsSingleHost(t *testing.T) {
	nets := parseCIDRs([]string{"::ffff:1.2.3.4"})
	if !ipInAny("1.2.3.4", nets) {
		t.Fatalf("parseCIDRs(::ffff:1.2.3.4) = %v: does not cover 1.2.3.4", nets)
	}
	for _, other := range []string{"::1", "::2", "1.2.3.5"} {
		if ipInAny(other, nets) {
			t.Fatalf("parseCIDRs(::ffff:1.2.3.4) = %v: also covers %s", nets, other)
		}
	}
}

// TestClientIP_XRealIPTrustedProxyAddressIsNotTheClient pins #4520 part 2: with
// X-Forwarded-For absent, an X-Real-IP value that is itself a trusted proxy is not
// returned as the client, and an earlier (client-suppliable) occurrence is not used
// in its place.
func TestClientIP_XRealIPTrustedProxyAddressIsNotTheClient(t *testing.T) {
	nets := parseCIDRs([]string{"10.0.0.0/8"})

	for name, values := range map[string][]string{
		"single trusted value":           {"10.0.0.7"},
		"client value then trusted last": {"1.2.3.4", "10.0.0.7"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:50000"
		for _, v := range values {
			req.Header.Add("X-Real-IP", v)
		}
		if got := clientIPFromRequest(req, nets); got != "" {
			t.Fatalf("%s %v: got %q, want \"\" (keep the TCP peer)", name, values, got)
		}
	}

	// An untrusted last value is still the client.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:50000"
	req.Header.Add("X-Real-IP", "10.0.0.7")
	req.Header.Add("X-Real-IP", "1.2.3.4")
	if got := clientIPFromRequest(req, nets); got != "1.2.3.4" {
		t.Fatalf("X-Real-IP [10.0.0.7, 1.2.3.4]: got %q, want 1.2.3.4", got)
	}
}
