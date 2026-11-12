package netutil

import (
	"fmt"
	"net"
	"testing"
)

// TestIsPrivateOrLinkLocalExceptLoopback pins the webhook-tier policy the three
// outbound-webhook guards (evidencesink, siem, notifychan) now delegate to: it
// must refuse everything IsPrivateOrLinkLocal refuses — including RFC-6598 CGNAT
// (100.64/10) and every embedded-IPv4 encoding — EXCEPT loopback, which it
// permits (direct and embedded).
func TestIsPrivateOrLinkLocalExceptLoopback(t *testing.T) {
	refused := []string{
		"169.254.169.254",    // IPv4 link-local / cloud IMDS
		"100.100.100.200",    // Alibaba IMDS, inside RFC-6598 CGNAT (F2)
		"100.64.0.1",         // RFC-6598 CGNAT
		"10.0.0.1",           // RFC-1918
		"192.168.0.1",        // RFC-1918
		"172.16.0.1",         // RFC-1918
		"169.254.0.1",        // link-local
		"0.0.0.0",            // "this network"
		"::",                 // unspecified
		"fe80::1",            // IPv6 link-local
		"fd00::1",            // IPv6 ULA
		"64:ff9b::a9fe:a9fe", // NAT64 well-known of IMDS (F1 encoding)
		"::a9fe:a9fe",        // IPv4-compatible of IMDS (F1 encoding)
		"64:ff9b::6440:1",    // NAT64 of 100.64.0.1 (CGNAT via encoding)
	}
	for _, s := range refused {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test vector %q did not parse", s)
		}
		if !IsPrivateOrLinkLocalExceptLoopback(ip) {
			t.Errorf("IsPrivateOrLinkLocalExceptLoopback(%s) = false, want true (must be refused)", s)
		}
	}

	permitted := []string{
		"127.0.0.1",        // IPv4 loopback — the one documented exception
		"127.1.2.3",        // rest of 127.0.0.0/8
		"::1",              // IPv6 loopback
		"::ffff:127.0.0.1", // IPv4-mapped loopback
		"64:ff9b::7f00:1",  // NAT64 of 127.0.0.1 — embedded loopback, still permitted
		"8.8.8.8",          // public
		"93.184.216.34",    // public
		"2001:db8::1",      // public IPv6 (documentation range, not Teredo)
		"64:ff9b::808:808", // NAT64 of public 8.8.8.8
	}
	for _, s := range permitted {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test vector %q did not parse", s)
		}
		if IsPrivateOrLinkLocalExceptLoopback(ip) {
			t.Errorf("IsPrivateOrLinkLocalExceptLoopback(%s) = true, want false (must be permitted)", s)
		}
	}
}

// TestIsPrivateOrLinkLocalExceptLoopback_IsIsPrivateOrLinkLocalMinusLoopback
// asserts the exact relationship to the backend tier across every embedded
// encoding of a wide octet sweep: the two predicates agree on every address
// that is NOT loopback, and differ exactly on loopback (backend refuses,
// webhook tier permits).
func TestIsPrivateOrLinkLocalExceptLoopback_IsIsPrivateOrLinkLocalMinusLoopback(t *testing.T) {
	encode := func(kind, a, b, c, d byte) net.IP {
		var s string
		switch kind {
		case 0:
			s = fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
		case 1:
			s = fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d)
		case 2:
			s = fmt.Sprintf("64:ff9b::%d.%d.%d.%d", a, b, c, d)
		case 3:
			s = fmt.Sprintf("64:ff9b:1::%d.%d.%d.%d", a, b, c, d)
		case 4:
			s = fmt.Sprintf("::%d.%d.%d.%d", a, b, c, d)
		case 5:
			s = fmt.Sprintf("2002:%02x%02x:%02x%02x::", a, b, c, d)
		default:
			s = fmt.Sprintf("2001::%02x%02x:%02x%02x", a^0xff, b^0xff, c^0xff, d^0xff)
		}
		return net.ParseIP(s)
	}
	octets := []byte{0, 1, 8, 10, 100, 127, 169, 172, 192, 254}
	for _, a := range octets {
		for _, d := range octets {
			for kind := range byte(7) {
				ip := encode(kind, a, 64, d, 1)
				if ip == nil {
					continue
				}
				backend := IsPrivateOrLinkLocal(ip)
				webhook := IsPrivateOrLinkLocalExceptLoopback(ip)
				loopback := ip.IsLoopback()
				if v4 := embeddedIPv4(ip); v4 != nil && v4.IsLoopback() {
					loopback = true
				}
				want := backend && !loopback
				if webhook != want {
					t.Fatalf("mismatch for %v (kind %d): webhook=%v backend=%v loopback=%v want %v",
						ip, kind, webhook, backend, loopback, want)
				}
			}
		}
	}
}
