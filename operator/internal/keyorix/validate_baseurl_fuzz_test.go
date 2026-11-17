package keyorix

import (
	"net"
	"net/url"
	"testing"
)

// FuzzValidateClientBaseURL drives validateClientBaseURL — the HTTP client's own
// last-line check that the destination it is about to send the machine-identity bearer
// token (and receive a plaintext secret value from) is a TLS endpoint. The security
// property: an ACCEPTED base URL is either https, or http to a genuine loopback host
// (the dev/test carve-out). Anything that would ship the token in cleartext to a
// non-loopback host must be rejected.
//
//	ACCEPTED(raw) ⟹ u.Host != "" AND ( u.Scheme == "https"
//	                                   OR (u.Scheme == "http" AND loopback(u.Hostname())) )
//
// The oracle computes loopback-ness INDEPENDENTLY from net.ParseIP / the literal
// "localhost", so a parser disagreement (e.g. a host that validateClientBaseURL reads
// as loopback but net/http would dial as a routable address, or vice-versa) is a real
// finding. What this does NOT verify: that the host is actually reachable, nor that the
// allow-list in the controller agrees — only the scheme/loopback cleartext gate.
func FuzzValidateClientBaseURL(f *testing.F) {
	seeds := []string{
		"https://keyorix.internal",
		"http://localhost",
		"http://127.0.0.1",
		"http://[::1]",
		"http://keyorix.internal",
		"https://",
		"http://localhost.evil.com",
		"HTTPS://keyorix.internal",
		"ftp://keyorix.internal",
		"https://user:pass@keyorix.internal",
		"http://127.0.0.1.evil.com",
		"//keyorix.internal",
		"http://0177.0.0.1",
		"http://2130706433", // 127.0.0.1 as a single integer
		"",
		"https://keyorix.internal:8443/path?x=1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		err := validateClientBaseURL(raw)
		if err != nil {
			return // rejected is always safe for a cleartext gate.
		}
		u, perr := url.Parse(raw)
		if perr != nil {
			t.Fatalf("validateClientBaseURL ACCEPTED %q but net/url cannot parse it: %v", raw, perr)
		}
		if u.Host == "" {
			t.Fatalf("validateClientBaseURL ACCEPTED %q but its Host is empty", raw)
		}
		if u.Scheme == "https" {
			return
		}
		if u.Scheme != "http" {
			t.Fatalf("validateClientBaseURL ACCEPTED %q with non-http(s) scheme %q — "+
				"the bearer token's transport is undefined", raw, u.Scheme)
		}
		// http accepted: the host MUST be loopback, computed independently.
		host := u.Hostname()
		if host == "localhost" {
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			t.Fatalf("validateClientBaseURL ACCEPTED http://%s (%q) but %q is NOT a loopback host — "+
				"the bearer token would travel in cleartext to a routable address", host, raw, host)
		}
	})
}
