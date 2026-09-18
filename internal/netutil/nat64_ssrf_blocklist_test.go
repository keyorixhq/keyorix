package netutil

import (
	"net"
	"testing"
)

// TestSSRFBlocklist_IPv4EmbeddingEncodings is the regression test for the NAT64 /
// IPv4-compatible SSRF blocklist bypass: IsPrivateOrLinkLocal (the SSRF blocklist
// shared by dynamic-secrets admin-DSN dials, Azure KMS endpoint dials, and
// validateAdminDSNHost) must reject a private/loopback/IMDS IPv4 address written
// in ANY IPv6 embedding, not just the raw IPv4 form.
//
// Go's net.IP.To4() folds IPv4-MAPPED (::ffff:x.x.x.x) into the IPv4 CIDRs
// automatically, but does NOT fold NAT64 (RFC 6052 64:ff9b::/96) or deprecated
// IPv4-compatible (::/96) addresses — those needed their own blocklist ranges.
// In a NAT64 deployment, [64:ff9b::a9fe:a9fe] routes to the cloud IMDS at
// 169.254.169.254, so leaving it off the blocklist was an SSRF bypass.
func TestSSRFBlocklist_IPv4EmbeddingEncodings(t *testing.T) {
	mustReject := []struct{ addr, why string }{
		{"::ffff:127.0.0.1", "IPv4-mapped loopback"},
		{"::ffff:169.254.169.254", "IPv4-mapped IMDS"},
		{"64:ff9b::7f00:1", "NAT64 of 127.0.0.1 (loopback)"},
		{"64:ff9b::a9fe:a9fe", "NAT64 of 169.254.169.254 (cloud IMDS)"},
		{"64:ff9b::a00:1", "NAT64 of 10.0.0.1 (RFC1918)"},
		{"64:ff9b::c0a8:1", "NAT64 of 192.168.0.1 (RFC1918)"},
		{"::7f00:1", "IPv4-compatible ::127.0.0.1 (loopback)"},
		{"::a9fe:a9fe", "IPv4-compatible ::169.254.169.254 (IMDS)"},
	}
	for _, tc := range mustReject {
		ip := net.ParseIP(tc.addr)
		if ip == nil {
			t.Fatalf("%s: net.ParseIP returned nil", tc.addr)
		}
		if !IsPrivateOrLinkLocal(ip) {
			t.Errorf("SSRF BYPASS: IsPrivateOrLinkLocal(%s) = false, must be true — %s reachable through the SSRF guard", tc.addr, tc.why)
		}
	}

	// The guard must still ALLOW genuinely public addresses (no over-block) —
	// including NAT64/IPv4-compatible embeddings of PUBLIC IPv4, which are the
	// legitimate egress path in an IPv6-only deployment. Blocking those (a
	// wholesale-prefix block would) breaks real traffic; the decode approach
	// permits them because the embedded IPv4 is public.
	mustAllow := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34",
		"2001:4860:4860::8888", "2606:4700:4700::1111",
		"64:ff9b::808:808",   // NAT64 of 8.8.8.8 (public) — must stay allowed
		"64:ff9b::5db8:d822", // NAT64 of 93.184.216.34 (public)
		"::808:808",          // IPv4-compatible ::8.8.8.8 (public)
	}
	for _, pub := range mustAllow {
		if ip := net.ParseIP(pub); ip != nil && IsPrivateOrLinkLocal(ip) {
			t.Errorf("OVER-BLOCK: IsPrivateOrLinkLocal(%s) = true, must be false — a public target must remain reachable", pub)
		}
	}
}
