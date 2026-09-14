package netutil

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsLinkLocal is the direction-both check for the F2 egress guard: it must
// refuse IPv4/IPv6 link-local (the cloud instance-metadata surface) while
// PERMITTING RFC-1918, loopback, and IPv6 ULA — the on-prem/dev targets a keyorix
// OIDC issuer legitimately runs on. This is precisely where it diverges from
// IsPrivateOrLinkLocal, so both are asserted on the same addresses.
func TestIsLinkLocal(t *testing.T) {
	cases := []struct {
		ip           string
		wantLinkLoc  bool
		wantPrivOrLL bool // for contrast: IsPrivateOrLinkLocal's verdict on the same IP
	}{
		{"169.254.169.254", true, true}, // cloud IMDS — the whole point
		{"169.254.0.1", true, true},     // IPv4 link-local
		{"fe80::1", true, true},         // IPv6 link-local
		{"10.0.0.5", false, true},       // RFC-1918: allowed by IsLinkLocal, blocked by IsPrivateOrLinkLocal
		{"192.168.1.10", false, true},   // RFC-1918
		{"172.16.9.9", false, true},     // RFC-1918
		{"127.0.0.1", false, true},      // loopback: allowed here (dev)
		{"::1", false, true},            // IPv6 loopback
		{"fd00::1", false, true},        // IPv6 ULA: allowed here
		{"8.8.8.8", false, false},       // public
		{"93.184.216.34", false, false}, // public
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := IsLinkLocal(ip); got != tc.wantLinkLoc {
			t.Errorf("IsLinkLocal(%s) = %v, want %v", tc.ip, got, tc.wantLinkLoc)
		}
		if got := IsPrivateOrLinkLocal(ip); got != tc.wantPrivOrLL {
			t.Errorf("IsPrivateOrLinkLocal(%s) = %v, want %v (contrast baseline)", tc.ip, got, tc.wantPrivOrLL)
		}
	}
}

// TestIsLinkLocal_DialerRefusesIMDSAllowsPrivate wires IsLinkLocal through the real
// Dialer to confirm the guard refuses a literal cloud-IMDS dial (the shape
// oidc_jwks.go / discoverOIDC use) while PERMITTING an RFC-1918 target — the exact
// behaviour that lets an on-prem OIDC issuer stay reachable.
func TestIsLinkLocal_DialerRefusesIMDSAllowsPrivate(t *testing.T) {
	var dialed string
	d := Dialer{
		Disallow: IsLinkLocal,
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return &fakeConn{}, nil
		},
	}

	_, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:443")
	require.Error(t, err, "cloud IMDS literal IP must be refused by the link-local guard")
	assert.Empty(t, dialed, "the underlying dial must never be reached for IMDS")

	_, err = d.DialContext(context.Background(), "tcp", "10.10.0.5:443")
	require.NoError(t, err, "an RFC-1918 on-prem issuer must remain reachable under the link-local guard")
	assert.Equal(t, "10.10.0.5:443", dialed)
}
