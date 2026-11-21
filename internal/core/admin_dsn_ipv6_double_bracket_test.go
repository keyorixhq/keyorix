package core

import "testing"

// TestAdminDSNHost_DoubleBracketIPv6_Blocked confirms that a double-bracket-wrapped
// IPv6 literal (e.g. host=[[::1]]) is rejected by validateAdminDSNHost.
//
// Before the SplitDSNHostList bracket-strip was a loop, a single if stripped
// [[::1]] once to [::1]; net.ParseIP("[::1]") returns nil and net.LookupHost("[::1]")
// errors, so the check was silently skipped — the registration succeeded despite
// naming a private/loopback host. FuzzDSNHostsCoverDriverHosts confirmed the
// discrepancy: pgx stores [[::1]] as the host (not stripping it), and the
// oracle's stripBrackets applied once does not normalise [[::1]] to ::1 the
// same way a loop would, flagging a coverage gap.
//
// Red/green: this test fails at origin/main (before the loop fix) and passes
// at HEAD (after). Proof: validateAdminDSNHost("host=[[::1]]") returns nil
// on main (skips the check) and a non-nil error at HEAD (blocks ::1 as
// private/loopback).
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
				t.Fatalf("validateAdminDSNHost(%q) returned nil — double-bracket private IPv6 was not blocked; expected an error rejecting the private/loopback address", tc.dsn)
			}
		})
	}
}
