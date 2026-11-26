// Package egressref is the independent reference model the site-wiring egress fuzz
// targets (V7-GAP-1) compare a real outbound transport against. It is imported only by
// _test.go files.
//
// Decode builds one destination address in one of ten encodings from four raw octets and
// states, from those octets alone, whether it is link-local and whether it is in the
// private tier. Neither verdict calls netutil: a bug in netutil's own CIDR tables or
// embedded-IPv4 decode cannot corrupt the expectation it is being checked against. The
// same discipline as isRawV4Private in internal/netutil/egress_dial_fuzz_test.go.
//
// Documented intentional differences between the guard tiers (each one is a deliberate
// policy choice, not an encoding gap; see docs/security/egress-inventory.md):
//
//   - IsLinkLocal (OIDC discovery and JWKS, Connect backends, Azure Graph) permits RFC-1918,
//     loopback, CGNAT, and IPv6 ULA. fd00:ec2::254 (AWS IPv6 IMDS) is in ULA and is
//     therefore permitted by it; netutil/dialer.go documents this as an accepted residual.
//   - IsPrivateOrLinkLocal (dynamic secrets, Azure KMS) refuses all of those, loopback
//     included.
//   - IsPrivateOrLinkLocalExceptLoopback (webhook tier) differs from it only by permitting
//     loopback, in direct and embedded encodings.
package egressref

import (
	"fmt"
	"net"
)

// Kinds is the number of encodings Decode understands.
const Kinds = 10

// Addr is one decoded destination with the reference verdicts for it.
type Addr struct {
	IP net.IP
	// Kind names the encoding, for failure messages.
	Kind string
	// LinkLocal is true when the address is, or embeds, an IPv4 169.254.0.0/16 address or
	// is a native fe80::/10 address.
	LinkLocal bool
	// Private is true when LinkLocal, or when it is, or embeds, an IPv4 address in
	// RFC-1918, loopback, 0.0.0.0/8 or RFC 6598, or is a native IPv6 ULA / loopback.
	Private bool
	// Loopback is true when it is, or embeds, 127.0.0.0/8 or is ::1.
	Loopback bool
}

// RawV4 reports the three verdicts for an IPv4 address from its first two octets (every
// range the guards name is decided by them).
func RawV4(a, b byte) (linkLocal, private, loopback bool) {
	linkLocal = a == 169 && b == 254
	loopback = a == 127
	private = linkLocal || loopback ||
		a == 10 ||
		(a == 172 && b >= 16 && b <= 31) ||
		(a == 192 && b == 168) ||
		a == 0 ||
		(a == 100 && b >= 64 && b <= 127)
	return linkLocal, private, loopback
}

// Decode builds the address for encoding kind (taken modulo Kinds) from the octets.
func Decode(kind, a, b, c, d byte) Addr {
	ll, priv, loop := RawV4(a, b)
	emb := func(name string, ip net.IP) Addr {
		return Addr{IP: ip, Kind: name, LinkLocal: ll, Private: priv, Loopback: loop}
	}
	v6 := func(prefix ...byte) net.IP {
		ip := make(net.IP, net.IPv6len)
		copy(ip, prefix)
		return ip
	}
	switch kind % Kinds {
	case 0:
		return emb("ipv4", net.IPv4(a, b, c, d))
	case 1:
		return emb("ipv4-mapped", net.ParseIP(fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d)))
	case 2: // RFC 6052 well-known NAT64 64:ff9b::/96
		ip := v6(0x00, 0x64, 0xff, 0x9b)
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		return emb("nat64-wellknown", ip)
	case 3: // RFC 8215 local-use 64:ff9b:1::/96
		ip := v6(0x00, 0x64, 0xff, 0x9b, 0x00, 0x01)
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		return emb("nat64-localuse", ip)
	case 4: // deprecated IPv4-compatible ::a.b.c.d
		ip := v6()
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		return emb("ipv4-compatible", ip)
	case 5: // 6to4 2002:AABB:CCDD::
		ip := v6(0x20, 0x02, a, b, c, d)
		return emb("6to4", ip)
	case 6: // Teredo 2001:0::/32, client IPv4 XOR 0xffffffff in the low 32 bits
		ip := v6(0x20, 0x01, 0x00, 0x00)
		ip[12], ip[13], ip[14], ip[15] = a^0xff, b^0xff, c^0xff, d^0xff
		return emb("teredo", ip)
	case 7: // native IPv6 link-local fe80::/10 (zone-less)
		ip := v6(0xfe, 0x80)
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		return Addr{IP: ip, Kind: "ipv6-linklocal", LinkLocal: true, Private: true}
	case 8: // native IPv6 ULA fc00::/7, plus AWS IPv6 IMDS fd00:ec2::254 when octets are 0
		ip := v6(0xfd, 0x00, 0x0e, 0xc2)
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		if a == 0 && b == 0 && c == 0 && d == 0 {
			ip = net.ParseIP("fd00:ec2::254")
		}
		return Addr{IP: ip, Kind: "ipv6-ula", Private: true}
	default: // IPv6 documentation range: public by every tier
		ip := v6(0x20, 0x01, 0x0d, 0xb8)
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		return Addr{IP: ip, Kind: "ipv6-public", LinkLocal: false, Private: false}
	}
}

// String renders the address and its encoding for failure messages.
func (a Addr) String() string { return fmt.Sprintf("%s(%s)", a.IP, a.Kind) }
