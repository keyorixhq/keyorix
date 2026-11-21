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

// TestParseCIDRs_IPv4MappedExplicitPrefix pins the prefixed form of #4520: an
// IPv4-mapped entry written with an explicit prefix of 32 or less covers the IPv4
// network it names, not the IPv6 network ::/N (which contains ::1), and a mapped
// prefix from 33 to 95 (no IPv4 meaning) trusts nothing.
func TestParseCIDRs_IPv4MappedExplicitPrefix(t *testing.T) {
	for _, tc := range []struct{ entry, in, out string }{
		{"::ffff:1.2.3.4/32", "1.2.3.4", "1.2.3.5"},
		{"::ffff:10.0.0.0/8", "10.9.9.9", "11.0.0.1"},
		{" ::ffff:192.168.1.0/24 ", "192.168.1.200", "192.168.2.1"},
	} {
		nets := parseCIDRs([]string{tc.entry})
		if !ipInAny(tc.in, nets) {
			t.Fatalf("parseCIDRs(%q) = %v: does not cover %s", tc.entry, nets, tc.in)
		}
		for _, other := range []string{"::1", "::2", tc.out} {
			if ipInAny(other, nets) {
				t.Fatalf("parseCIDRs(%q) = %v: also covers %s", tc.entry, nets, other)
			}
		}
	}

	for _, entry := range []string{"::ffff:1.2.3.4/64", "::ffff:1.2.3.4/33", "::ffff:1.2.3.4/95"} {
		if nets := parseCIDRs([]string{entry}); len(nets) != 0 {
			t.Fatalf("parseCIDRs(%q) = %v: want no trusted network", entry, nets)
		}
	}

	// From /96 up a mapped entry is an ordinary IPv6 network over the mapped range.
	nets := parseCIDRs([]string{"::ffff:10.0.0.0/104"})
	if !ipInAny("10.1.2.3", nets) || ipInAny("::1", nets) {
		t.Fatalf("parseCIDRs(::ffff:10.0.0.0/104) = %v: want exactly 10.0.0.0/8", nets)
	}

	// The effect: a local ::1 peer is not a trusted proxy, so its X-Forwarded-For
	// is ignored; the intended IPv4 proxy's is honoured.
	nets = parseCIDRs([]string{"::ffff:1.2.3.4/32"})
	for remote, want := range map[string]string{"[::1]:50000": "", "1.2.3.4:50000": "6.6.6.6"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		if got := clientIPFromRequest(req, nets); got != want {
			t.Fatalf("peer %s, XFF 6.6.6.6: got %q, want %q", remote, got, want)
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
