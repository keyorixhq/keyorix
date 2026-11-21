package core

import "testing"

// TestAdminDSNHost_DoubleBracketIPv6_Blocked pins that a host written with two
// bracket layers (e.g. host=[[::1]]) is validated like the single-layer form: it
// must be refused when it names a private, loopback or link-local address.
// SplitDSNHostList strips every outer bracket pair, so the validator sees the bare
// address. Red without the loop in SplitDSNHostList, green with it.
func TestAdminDSNHost_DoubleBracketIPv6_Blocked(t *testing.T) {
	cases := []struct {
		desc string
		dsn  string
	}{
		{"double-bracket IPv6 loopback", "host=[[::1]]"},
		{"double-bracket IPv6 link-local", "host=[[fe80::1]]"},
		{"double-bracket IPv6 unique-local", "host=[[fc00::1]]"},
		{"double-bracket IPv6 loopback multi-host", "host=[[::1]],203.0.113.5"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			if err := validateAdminDSNHost(tc.dsn); err == nil {
				t.Fatalf("validateAdminDSNHost(%q) returned nil, want an error for a private address written with two bracket layers", tc.dsn)
			}
		})
	}
}
