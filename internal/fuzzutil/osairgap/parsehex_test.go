package osairgap

import (
	"net"
	"testing"
)

// TestParseHexAddr_V6WordOrder pins the /proc/net/tcp6 decode: the kernel
// prints each 32-bit word of the address in host (little-endian) order, so the
// bytes inside every word must be reversed. A straight copy decodes the real ::1
// row as ::100:0 (not loopback), which makes the sampler report plain IPv6
// loopback as egress and every real v6 peer under the wrong address.
func TestParseHexAddr_V6WordOrder(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want net.IP
	}{
		{"loopback ::1", "00000000000000000000000001000000:0035", net.ParseIP("::1")},
		{"external 2001:db8::1", "B80D01200000000000000000" + "01000000:01BB", net.ParseIP("2001:db8::1")},
		{"v4-mapped ::ffff:8.8.8.8", "0000000000000000FFFF000008080808:0050", net.ParseIP("::ffff:8.8.8.8")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip, _, ok := parseHexAddr(c.hex, true)
			if !ok {
				t.Fatalf("parseHexAddr(%q) failed", c.hex)
			}
			if !ip.Equal(c.want) {
				t.Fatalf("parseHexAddr(%q) = %s, want %s", c.hex, ip, c.want)
			}
		})
	}

	lo, _, _ := parseHexAddr("00000000000000000000000001000000:0035", true)
	if !lo.IsLoopback() {
		t.Fatalf("::1 row decoded to %s, IsLoopback()=false", lo)
	}
	ext, _, _ := parseHexAddr("B80D01200000000000000000"+"01000000:01BB", true)
	if ok, _ := (Allowlist{}).Classify(Endpoint{IP: ext, Port: 443}); ok {
		t.Fatalf("external v6 peer %s was classified as allowed", ext)
	}
}
