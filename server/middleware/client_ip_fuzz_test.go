package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzClientIPParsing drives parseCIDRs and clientIPFromRequest with hostile
// inputs. These are on the hot path of every HTTP request: parseCIDRs turns
// server.http.trusted_proxies (operator-controlled config) into net.IPNet
// values; clientIPFromRequest then walks the X-Forwarded-For header (fully
// attacker-controlled) to decide the real client IP, which keys the per-IP
// login/MFA brute-force rate limiter and PAT/machine-token CIDR allowlist
// checks. A bug allowing a client to forge its apparent source IP defeats
// those controls.
//
// Oracles — all fatal (the code is in production and must hold today):
//
//	(a) parseCIDRs: never panics on any input; silently skips unparse-able
//	    entries rather than propagating errors.
//	(b) parseCIDRs COVERAGE: a bare IPv4 "d.d.d.d" accepted by net.ParseIP
//	    is treated as /32 and covers exactly that host.  A bare IPv6 address
//	    is treated as /128 and covers exactly that host.
//	(c) parseCIDRs DETERMINISM: same input → same number of parsed nets.
//	(d) clientIPFromRequest NEVER-PANIC: does not panic on arbitrary
//	    RemoteAddr, X-Forwarded-For, or X-Real-IP values.
//	(e) UNTRUSTED-PEER BLOCKS: when the RemoteAddr is NOT in the trusted
//	    set, the returned IP is always "" — an untrusted client cannot inject
//	    a fake source IP via forwarding headers.
//	(f) SINGLE-HOP BYPASS: when RemoteAddr IS trusted, XFF is exactly one
//	    valid IP that is NOT trusted, and X-Real-IP is absent, the returned
//	    IP equals that single XFF entry.
//	(g) RESULT IS VALID IP: a non-empty return value must parse as a valid
//	    IP address via net.ParseIP.
//	(h) RESULT NOT TRUSTED: a non-empty return value taken from X-Forwarded-For
//	    is never itself in the trusted set (a trusted proxy's own address cannot
//	    appear as the "real" client). Not checked for the X-Real-IP fallback,
//	    which clientIPFromRequest returns without a trust check by design.
//
// What this does NOT verify: that ClientIP correctly rewrites r.RemoteAddr
// (HTTP middleware layer), the X-Forwarded-Proto / ForwardedHTTPS path, the
// rate-limiting logic keyed on the resulting IP, or whether a multi-hop XFF
// chain always returns the leftmost non-trusted hop (the per-hop walk is
// exercised via oracle (f) only for the single-hop simple case).
func FuzzClientIPParsing(f *testing.F) {
	// Seeds: (trustedList, remoteAddr, xffHeader, xrealipHeader)
	// trustedList entries separated by newline
	seeds := []struct {
		trusted, remote, xff, xrip string
	}{
		// No trusted proxies — headers must be ignored.
		{"", "1.2.3.4:50000", "10.0.0.1", ""},
		// Trusted peer, single non-trusted XFF hop.
		{"10.0.0.0/8", "10.0.0.1:50000", "1.2.3.4", ""},
		// Trusted peer, all trusted XFF hops → no non-trusted hop.
		{"10.0.0.0/8", "10.0.0.1:50000", "10.0.0.5", ""},
		// Bare IP as trusted proxy entry (no /mask).
		{"10.0.0.1", "10.0.0.1:50000", "1.2.3.4", ""},
		// Peer not in trusted list.
		{"10.0.0.0/8", "5.5.5.5:50000", "1.2.3.4", ""},
		// XFF with multiple hops: rightmost-trusted should stop.
		{"10.0.0.0/8", "10.0.0.1:50000", "1.2.3.4,10.0.0.5", ""},
		// X-Real-IP fallback when XFF absent.
		{"10.0.0.0/8", "10.0.0.1:50000", "", "1.2.3.4"},
		// IPv6 trusted proxy.
		{"::1/128", "[::1]:50000", "2001:db8::1", ""},
		// Malformed XFF entry mixed with valid.
		{"10.0.0.0/8", "10.0.0.1:50000", "not-an-ip,1.2.3.4", ""},
		// Empty XFF.
		{"10.0.0.0/8", "10.0.0.1:50000", "", ""},
		// Garbage CIDR in trusted list.
		{"not-a-cidr\n10.0.0.0/8", "10.0.0.1:50000", "1.2.3.4", ""},
		// Blank entries in trusted list.
		{"\n\n10.0.0.0/8\n", "10.0.0.1:50000", "1.2.3.4", ""},
		// X-Real-IP fallback returning an address inside the trusted set (found by
		// the fuzzer; oracle (h) covers the XFF walk only).
		{"0.0.0.0/0", "1.2.3.4:50000", "", "0.0.0.0"},
	}
	for _, s := range seeds {
		f.Add(s.trusted, s.remote, s.xff, s.xrip)
	}

	f.Fuzz(func(t *testing.T, trustedRaw, remoteAddr, xffHeader, xrealipHeader string) {
		// Cap inputs to avoid oversized allocations.
		if len(trustedRaw) > 4096 || len(xffHeader) > 4096 || len(remoteAddr) > 256 || len(xrealipHeader) > 256 {
			return
		}

		// Split newline-separated trusted entries.
		var entries []string
		for e := range strings.SplitSeq(trustedRaw, "\n") {
			entries = append(entries, e)
		}

		// Oracle (a)+(c): parseCIDRs must not panic, and must be deterministic.
		var nets []*net.IPNet
		fuzzutil.Guard(t.Fatalf, "parseCIDRs", func() {
			nets = parseCIDRs(entries)
		})
		nets2 := parseCIDRs(entries)
		if len(nets) != len(nets2) {
			t.Fatalf("parseCIDRs non-deterministic: got %d then %d nets for %q", len(nets), len(nets2), trustedRaw)
		}

		// Oracle (b): bare IPv4/IPv6 accepted as /32 or /128.
		for _, e := range entries {
			e = strings.TrimSpace(e)
			if e == "" || strings.Contains(e, "/") {
				continue
			}
			ip := net.ParseIP(e)
			if ip == nil {
				continue // garbage — expected to be dropped
			}
			found := false
			for _, n := range nets {
				if n.Contains(ip) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("parseCIDRs(%q): bare IP %q parsed OK but no net covers it (got %v)", trustedRaw, e, nets)
			}
		}

		// Build a request with the fuzzed headers.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if remoteAddr != "" {
			req.RemoteAddr = remoteAddr
		}
		if xffHeader != "" {
			req.Header.Set("X-Forwarded-For", xffHeader)
		}
		if xrealipHeader != "" {
			req.Header.Set("X-Real-IP", xrealipHeader)
		}

		// Oracle (d): clientIPFromRequest must not panic.
		var got string
		fuzzutil.Guard(t.Fatalf, "clientIPFromRequest", func() {
			got = clientIPFromRequest(req, nets)
		})

		// Oracle (e): untrusted peer → always "".
		if !peerIsTrustedProxy(req, nets) {
			if got != "" {
				t.Fatalf("clientIPFromRequest: untrusted peer %q returned %q (want \"\")", remoteAddr, got)
			}
			return
		}

		if got == "" {
			return // trusted peer but no suitable hop — valid outcome, nothing more to check
		}

		// Oracle (g): non-empty result must be a valid IP.
		if net.ParseIP(got) == nil {
			t.Fatalf("clientIPFromRequest: returned non-empty %q that net.ParseIP rejects", got)
		}

		// Oracle (h): an X-Forwarded-For result must not be in the trusted set. The
		// X-Real-IP fallback (XFF absent or blank) is exempt: it carries no chain and
		// is returned as the trusted proxy wrote it, without a trust check.
		xffUsed := strings.TrimSpace(xffHeader) != ""
		if xffUsed && ipInAny(got, nets) {
			t.Fatalf("clientIPFromRequest: returned %q which is itself a trusted proxy", got)
		}

		// Oracle (f): single-hop bypass — if XFF is exactly one valid non-trusted IP
		// and X-Real-IP is absent, the result must equal that IP.
		if xrealipHeader == "" {
			parts := strings.Split(xffHeader, ",")
			if len(parts) == 1 {
				hop := strings.TrimSpace(parts[0])
				if net.ParseIP(hop) != nil && !ipInAny(hop, nets) && got != hop {
					t.Fatalf("clientIPFromRequest: single-hop XFF %q → got %q (want %q)", xffHeader, got, hop)
				}
			}
		}
	})
}
