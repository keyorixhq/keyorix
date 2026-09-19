package netutil

import (
	"net"
	"testing"
)

// TestIsLinkLocal_IPv4EmbeddingEncodings is IsLinkLocal's counterpart to
// TestSSRFBlocklist_IPv4EmbeddingEncodings (nat64_ssrf_blocklist_test.go), which
// covers IsPrivateOrLinkLocal only. IsLinkLocal needed the identical
// embedded-IPv4-decode fix for the same reason: a link-local IPv4 address (in
// particular cloud IMDS, 169.254.169.254) written as a NAT64 (RFC 6052
// 64:ff9b::/96) or deprecated IPv4-compatible (::x) IPv6 address must still be
// refused — no caller of the narrower IsLinkLocal predicate (the JWKS/OIDC
// egress guard, or internal/connect's hardened transport) has any legitimate
// reason to reach IMDS via either encoding.
func TestIsLinkLocal_IPv4EmbeddingEncodings(t *testing.T) {
	mustReject := []struct{ addr, why string }{
		{"::ffff:169.254.169.254", "IPv4-mapped IMDS"},
		{"64:ff9b::a9fe:a9fe", "NAT64 of 169.254.169.254 (cloud IMDS)"},
		{"64:ff9b::a9fe:1", "NAT64 of 169.254.0.1 (IPv4 link-local)"},
		{"::a9fe:a9fe", "IPv4-compatible ::169.254.169.254 (IMDS)"},
	}
	for _, tc := range mustReject {
		ip := net.ParseIP(tc.addr)
		if ip == nil {
			t.Fatalf("%s: net.ParseIP returned nil", tc.addr)
		}
		if !IsLinkLocal(ip) {
			t.Errorf("SSRF BYPASS: IsLinkLocal(%s) = false, must be true — %s reachable through the link-local guard", tc.addr, tc.why)
		}
	}

	// Must still ALLOW a NAT64/compat encoding of a genuinely private (RFC-1918)
	// or public IPv4 — IsLinkLocal's whole point is to be narrower than
	// IsPrivateOrLinkLocal, and that must hold in every encoding, not just the
	// raw IPv4 form (matching TestIsLinkLocal's own raw-form cases).
	mustAllow := []struct{ addr, why string }{
		{"64:ff9b::a00:1", "NAT64 of 10.0.0.1 (RFC-1918, legitimate on-prem)"},
		{"64:ff9b::c0a8:1", "NAT64 of 192.168.0.1 (RFC-1918)"},
		{"64:ff9b::808:808", "NAT64 of 8.8.8.8 (public)"},
		{"::a00:1", "IPv4-compatible ::10.0.0.1 (RFC-1918)"},
	}
	for _, tc := range mustAllow {
		ip := net.ParseIP(tc.addr)
		if ip == nil {
			t.Fatalf("%s: net.ParseIP returned nil", tc.addr)
		}
		if IsLinkLocal(ip) {
			t.Errorf("OVER-BLOCK: IsLinkLocal(%s) = true, must be false — %s must remain reachable under the narrower link-local-only guard", tc.addr, tc.why)
		}
	}
}
