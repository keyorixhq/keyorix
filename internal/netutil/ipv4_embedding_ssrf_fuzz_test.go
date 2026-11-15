package netutil

import (
	"fmt"
	"net"
	"testing"
)

// FuzzIPv4EmbeddingSSRFParity is the encoding-parity invariant that locks the NAT64 /
// IPv4-compatible SSRF blocklist bypass class comprehensively (not just the specific
// literals in the regression test): for ANY IPv4 address, the SSRF verdict of
// IsPrivateOrLinkLocal must be identical whether that host is written as raw IPv4 or as
// any IPv6 encoding that denotes the same host — IPv4-mapped (::ffff:x), NAT64
// well-known (64:ff9b::x), NAT64 local-use (64:ff9b:1::x, RFC 8215), deprecated
// IPv4-compatible (::x), 6to4 (2002:WWXX:YYZZ::, RFC 3056), or Teredo (2001::/32 with
// the low 32 bits XOR-obfuscated, RFC 4380). They all route to the
// same IPv4 host, so a verdict that differs across encodings is exactly an SSRF gap: a
// private target reachable through an encoding the blocklist forgot (bypass), or a
// public target blocked through one encoding (over-block that breaks IPv6-only NAT64
// egress).
//
// Sound: correct code gives one host one verdict, so this false-positives on nothing.
// Red-proof: dropping embeddedIPv4() (or its NAT64/compat branch) makes the NAT64/compat
// verdict for a private IPv4 diverge from raw -> fires. Wholesale-blocking 64:ff9b::/96
// instead of decoding makes the NAT64 verdict for a PUBLIC IPv4 diverge -> also fires.
//
// 0.0.0.0/8 is excluded: it is reserved "this network" and its IPv4-compatible embedding
// ::a.b.c.d collides with :: (unspecified) and ::1 (loopback), where a per-host parity is
// not meaningful (::1 is loopback regardless of the "0.0.0.1" it nominally embeds).
func FuzzIPv4EmbeddingSSRFParity(f *testing.F) {
	seeds := [][4]byte{
		{127, 0, 0, 1}, {169, 254, 169, 254}, {10, 0, 0, 1}, {192, 168, 1, 1},
		{172, 16, 0, 1}, {172, 31, 255, 255}, {100, 64, 0, 1}, {100, 127, 255, 255},
		{8, 8, 8, 8}, {1, 1, 1, 1}, {93, 184, 216, 34}, {169, 253, 255, 255},
		{11, 0, 0, 1}, {172, 15, 0, 1}, {100, 63, 255, 255},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2], s[3])
	}

	f.Fuzz(func(t *testing.T, a, b, c, d byte) {
		if a == 0 {
			return // 0.0.0.0/8 reserved; compat form collides with ::/::1
		}
		v4 := net.IPv4(a, b, c, d)
		want := IsPrivateOrLinkLocal(v4)

		mapped := net.ParseIP(fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d))

		nat64 := make(net.IP, net.IPv6len)
		copy(nat64, nat64WellKnownPrefix.IP)
		nat64[12], nat64[13], nat64[14], nat64[15] = a, b, c, d

		compat := make(net.IP, net.IPv6len)
		compat[12], compat[13], compat[14], compat[15] = a, b, c, d

		// NAT64 local-use (RFC 8215, 64:ff9b:1::/96) carries the IPv4 in the low 32
		// bits exactly like the well-known prefix; the only difference is the prefix.
		localNat64 := make(net.IP, net.IPv6len)
		copy(localNat64, nat64LocalUsePrefix96.IP)
		localNat64[12], localNat64[13], localNat64[14], localNat64[15] = a, b, c, d

		// 6to4 (RFC 3056, 2002::/16) embeds the IPv4 directly in the next 32 bits
		// (bytes 2..5), not the low 32 bits.
		sixToFour := make(net.IP, net.IPv6len)
		copy(sixToFour, sixToFourPrefix.IP)
		sixToFour[2], sixToFour[3], sixToFour[4], sixToFour[5] = a, b, c, d

		// Teredo (RFC 4380, 2001::/32) carries the client IPv4 in the low 32 bits
		// XORed with 0xffffffff (anti-middlebox obfuscation); the decoder must undo
		// that XOR, so the encoding here must apply it.
		teredo := make(net.IP, net.IPv6len)
		copy(teredo, teredoPrefix.IP)
		teredo[12], teredo[13], teredo[14], teredo[15] = a^0xff, b^0xff, c^0xff, d^0xff

		for _, enc := range []struct {
			name string
			ip   net.IP
		}{
			{"ipv4-mapped", mapped},
			{"nat64-wellknown", nat64},
			{"ipv4-compatible", compat},
			{"nat64-local-use", localNat64},
			{"6to4", sixToFour},
			{"teredo", teredo},
		} {
			if enc.ip == nil {
				t.Fatalf("failed to build %s encoding for %d.%d.%d.%d", enc.name, a, b, c, d)
			}
			if got := IsPrivateOrLinkLocal(enc.ip); got != want {
				t.Fatalf("ENCODING PARITY: IsPrivateOrLinkLocal disagrees for host %d.%d.%d.%d: raw=%v but %s(%s)=%v — same host, different SSRF verdict across encodings is a blocklist gap", a, b, c, d, want, enc.name, enc.ip, got)
			}
		}
	})
}
