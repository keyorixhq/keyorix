package core

// FuzzAdminDSNHostSSRFGuard fuzzes validateAdminDSNHost — the dynamic-secrets admin-DSN SSRF guard
// that stops an operator from pointing a backend at a private/link-local address (RFC 1918,
// loopback, or the cloud IMDS 169.254.169.254) and using Keyorix as an SSRF proxy. The guard must
// extract the host from any of the supported DSN formats (URL, PostgreSQL key-value, MySQL
// @tcp()/@() wrappers, and the kubernetes JSON api_server blob) and block it if it is private. This
// multi-format parser has a track record of format-specific bypasses (the kubernetes-JSON blob and
// the IPv6-zone literal each silently skipped the check until fixed); it had no fuzz coverage.
//
// Sound metamorphic invariant (assert only the deny direction — a private host must ALWAYS be
// rejected, so it cannot false-positive): for a private IPv4 literal H (by the guard's own
// isPrivateIP), embedding H into ANY supported DSN format must make validateAdminDSNHost reject it.
// A format whose parser fails to surface H to the private-IP check is an SSRF bypass. Public hosts
// need no assertion (the guard may accept them). IPv4-focused so every format embeds a well-formed
// DSN; IPv6 literals / multi-host DSNs are a documented follow-up.

import (
	"fmt"
	"net"
	"testing"
)

func FuzzAdminDSNHostSSRFGuard(f *testing.F) {
	// (octet1..4, fmtSel) seeds: IMDS, loopback, RFC1918, CGNAT, and a public control, across formats.
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(0)) // IMDS via URL-form
	f.Add(byte(127), byte(0), byte(0), byte(1), byte(1))       // loopback via key-value
	f.Add(byte(10), byte(0), byte(0), byte(5), byte(2))        // RFC1918 via @tcp()
	f.Add(byte(192), byte(168), byte(1), byte(1), byte(3))     // RFC1918 via @()
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(4)) // IMDS via kubernetes JSON
	f.Add(byte(8), byte(8), byte(8), byte(8), byte(0))         // public control (no assertion)

	f.Fuzz(func(t *testing.T, o1, o2, o3, o4, fmtSel byte) {
		host := fmt.Sprintf("%d.%d.%d.%d", o1, o2, o3, o4)
		ip := net.ParseIP(host)
		if ip == nil || !isPrivateIP(ip) {
			return // only a private literal must be blocked; public/other are the guard's to allow
		}

		var dsn, form string
		switch fmtSel % 5 {
		case 0:
			form, dsn = "url", "postgres://user:pass@"+host+":5432/db"
		case 1:
			form, dsn = "keyvalue", "host="+host+" port=5432 user=u dbname=d"
		case 2:
			form, dsn = "mysql-tcp", "user:pass@tcp("+host+":3306)/db"
		case 3:
			form, dsn = "mysql-paren", "user:pass@("+host+":3306)/db"
		default:
			form, dsn = "kubernetes-json", `{"api_server":"https://`+host+`:6443","token":"t"}`
		}

		if err := validateAdminDSNHost(dsn); err == nil {
			t.Fatalf("SSRF BYPASS: private admin_dsn host %q was ACCEPTED by the guard in %s format: dsn=%q", host, form, dsn)
		}
	})
}
