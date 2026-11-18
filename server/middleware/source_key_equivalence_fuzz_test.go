// source_key_equivalence_fuzz_test.go — FuzzSourceRateLimitKeyEquivalence (RL1).
//
// Metamorphic fuzzer over the SOURCE-attribution pipeline that every per-source
// rate limiter / lockout counter keys on. The production key is:
//
//	ClientIP middleware rewrites r.RemoteAddr from X-Forwarded-For / X-Real-IP,
//	BUT only when the immediate TCP peer is a configured trusted proxy
//	(client_ip.go); then every per-source limiter keys on
//	core.CanonicalIP(r.RemoteAddr) (rate_limit.go, the gRPC IP fallback, and the
//	HTTP handlers that derive a key from r.RemoteAddr directly).
//
// A lockout/rate-limit bypass exists if two EQUIVALENT presentations of the same
// source land in DIFFERENT buckets (an attacker gets a fresh N-attempt budget per
// presentation); a targeted DoS exists if an UNAUTHENTICATED caller can, by
// setting forwarding headers, move the attributed key onto a victim's source (so
// the victim, not the attacker, absorbs the lockout) when no trusted proxy is in
// front — or spoof a different source from behind one by prepending a hop.
//
// Oracles (each returns an error, not t.Fatalf, so the red-proof unit tests can
// feed a deliberately-broken pipeline and show the oracle goes red WITHOUT
// editing production code — the fold_oracles_fuzz_test.go pattern):
//
//  1. CONVERGENCE: equivalent textual presentations of one net.IP (ephemeral
//     port, bracketed vs bare IPv6, upper/lower hex, zero-expanded IPv6,
//     IPv4-mapped ::ffff:a.b.c.d) collapse to ONE core.CanonicalIP key.
//  2. UNTRUSTED PEER ⇒ HEADERS INERT: with no trusted proxy in front (empty
//     trusted set), NO forwarding header the attacker sets may move the source
//     key off the TCP peer. This is the anti-spoof AND anti-targeted-DoS oracle.
//  3. TRUSTED PEER ⇒ LEFTMOST PREPEND IGNORED: behind a trusted proxy, prepending
//     attacker-controlled hop(s) to the LEFT of the X-Forwarded-For chain never
//     changes the attributed key (the walk is right→left, stopping at the first
//     non-trusted hop; a classic left-to-right RealIP parse would fail this).
//
// What this target does NOT verify (stated so the claim is checkable):
//   - It does not run the real limiter counting/storage — FuzzLoginThrottle
//     Concurrency (server/http/handlers) covers slot-counting and the per-account
//     lockout-never-bypassed property over a real storage-backed core. This target
//     covers ONLY the source-KEY equivalence/anti-spoof surface that one does not.
//   - It does not assert anything about IPv6 ZONE IDs (fe80::1%eth0): net.ParseIP
//     rejects a zone, so CanonicalIP returns it verbatim — two zone forms of one
//     link-local address are distinct keys. That is an EXPECTED-DIFFERENCE for a
//     non-routable link-local source (see the RL1 report), not asserted here.
//   - It does not test Forwarded (RFC 7239): client_ip.go reads only
//     X-Forwarded-For / X-Real-IP, so a "Forwarded:" header is inert by
//     construction (covered as a sub-case of oracle 2 — any header is inert when
//     untrusted).
//   - Resource meters (resguard) are intentionally NOT wired: the whole pipeline
//     is net.ParseIP + bounded header parsing with no per-input allocation
//     amplification, disk, net, or sleep. Target B (internal/core) carries the
//     bounded-memory oracle.
package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

// keyFn is the source-attribution pipeline reduced to its signature so a broken
// implementation can be substituted in the red-proof tests.
type keyFn func(peer string, trusted []*net.IPNet, h http.Header) string

// canonFn is core.CanonicalIP reduced to its signature for the same reason.
type canonFn func(addr string) string

// realSourceKey is the production pipeline: ClientIP's extraction (honouring
// forwarding headers only behind a trusted proxy) then core.CanonicalIP.
func realSourceKey(peer string, trusted []*net.IPNet, h http.Header) string {
	r := &http.Request{RemoteAddr: peer, Header: h}
	if ip := clientIPFromRequest(r, trusted); ip != "" {
		r.RemoteAddr = ip
	}
	return core.CanonicalIP(r.RemoteAddr)
}

// ipFromBytes builds a 4- or 16-byte net.IP from fuzz bytes, or nil if too short.
func ipFromBytes(b []byte) net.IP {
	switch {
	case len(b) >= 16:
		return net.IP(append([]byte(nil), b[:16]...))
	case len(b) >= 4:
		return net.IP(append([]byte(nil), b[:4]...))
	default:
		return nil
	}
}

// expandIPv6 renders ip as 8 fully-written hextets (no "::" compression), an
// equivalent textual form net.ParseIP accepts.
func expandIPv6(ip net.IP) string {
	v6 := ip.To16()
	if v6 == nil {
		return ip.String()
	}
	parts := make([]string, 8)
	for i := range 8 {
		parts[i] = fmt.Sprintf("%02x%02x", v6[2*i], v6[2*i+1])
	}
	return strings.Join(parts, ":")
}

// equivalentIPForms returns textual presentations of ip that all denote the SAME
// source and so MUST collapse to one CanonicalIP key. Only forms net.ParseIP(host)
// accepts as Equal to ip are returned (a presentation the parser rejects is not a
// claim about equivalence this oracle makes).
func equivalentIPForms(ip net.IP) []string {
	canon := ip.String()
	cands := []string{canon, strings.ToUpper(canon)}
	if ip.To4() != nil {
		cands = append(cands, canon+":54321", canon+":1", "::ffff:"+canon, "[::ffff:"+canon+"]:9")
	} else {
		cands = append(cands, "["+canon+"]:54321", "["+canon+"]", expandIPv6(ip), strings.ToUpper(expandIPv6(ip)))
	}
	// Keep only forms whose host parses back to the same address.
	out := cands[:0:0]
	for _, c := range cands {
		host := c
		if h, _, err := net.SplitHostPort(c); err == nil {
			host = h
		}
		if p := net.ParseIP(host); p != nil && p.Equal(ip) {
			out = append(out, c)
		}
	}
	return out
}

// checkConvergence asserts every equivalent presentation of ip yields one key.
func checkConvergence(ip net.IP, canon canonFn) error {
	forms := equivalentIPForms(ip)
	if len(forms) < 2 {
		return nil
	}
	want := canon(forms[0])
	for _, f := range forms[1:] {
		if got := canon(f); got != want {
			return fmt.Errorf("CONVERGENCE: equivalent source forms land in different buckets: canon(%q)=%q but canon(%q)=%q — a reconnecting/re-encoding attacker gets a fresh attempt budget per form",
				forms[0], want, f, got)
		}
	}
	return nil
}

// untrustedTrustSets returns trusted-proxy configurations under which `peer` is
// NOT trusted, so forwarding headers must be ignored entirely.
func untrustedTrustSets(peer string) [][]*net.IPNet {
	sets := [][]*net.IPNet{parseCIDRs(nil)} // no proxies configured (safe default)
	fixed := parseCIDRs([]string{"203.0.113.0/24", "2001:db8:dead::/48"})
	if !peerIsTrustedProxy(&http.Request{RemoteAddr: peer}, fixed) {
		sets = append(sets, fixed)
	}
	return sets
}

// checkUntrustedHeadersInert asserts no header moves the key off the peer when the
// peer is not a trusted proxy (anti-spoof + anti-targeted-DoS).
func checkUntrustedHeadersInert(peer string, h http.Header, key keyFn) error {
	for _, trusted := range untrustedTrustSets(peer) {
		base := key(peer, trusted, http.Header{})
		got := key(peer, trusted, h)
		if got != base {
			return fmt.Errorf("UNTRUSTED-INERT: peer %q not a trusted proxy, yet attacker headers moved the source key %q -> %q (a non-authenticated caller can pin lockout on a victim IP, or evade its own bucket)",
				peer, base, got)
		}
	}
	return nil
}

// prependOracleRealClient is a fixed, guaranteed-non-trusted client used as the
// RIGHTMOST (real) X-Forwarded-For hop in checkTrustedPrependIgnored, so the
// attacker's fuzzed prefix sits strictly to its LEFT.
const prependOracleRealClient = "198.51.100.42"

// checkTrustedPrependIgnored asserts that, behind a trusted proxy, an attacker
// prepending arbitrary hop(s) to the LEFT of the real client's X-Forwarded-For
// entry never changes the attributed key: the right→left walk must return the
// real client (the rightmost non-trusted hop) regardless of the prefix. (The
// weaker "any prepend is inert" is NOT asserted — a prepend legitimately adds the
// first client-attributable hop when the base chain had none; this oracle anchors
// a real client as the rightmost hop so the prefix is purely adversarial.)
func checkTrustedPrependIgnored(peer string, spoof string, key keyFn) error {
	trusted := parseCIDRs([]string{hostOnly(peer)})
	if !peerIsTrustedProxy(&http.Request{RemoteAddr: peer}, trusted) {
		return nil // peer is not a parseable IP; the trusted-proxy branch is unreachable
	}
	if hostOnly(peer) == prependOracleRealClient {
		return nil // peer must differ from the real client for this scenario
	}
	base := http.Header{}
	base.Set("X-Forwarded-For", prependOracleRealClient)
	withSpoof := http.Header{}
	withSpoof.Set("X-Forwarded-For", spoof+", "+prependOracleRealClient)
	want := key(peer, trusted, base)
	got := key(peer, trusted, withSpoof)
	if got != want {
		return fmt.Errorf("TRUSTED-PREPEND: behind trusted proxy %q, a left-prepended spoof %q changed the attributed key %q -> %q (XFF must be walked right→left)",
			peer, spoof, want, got)
	}
	if exp := core.CanonicalIP(prependOracleRealClient); want != exp {
		return fmt.Errorf("TRUSTED-PREPEND: behind trusted proxy %q, attributed %q but the real rightmost client is %q",
			peer, want, exp)
	}
	return nil
}

func FuzzSourceRateLimitKeyEquivalence(f *testing.F) {
	seeds := []struct {
		ipb  []byte
		hdr  string
		rest string
	}{
		{[]byte{1, 2, 3, 4}, "9.9.9.9", "198.51.100.7"},
		{[]byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "::1", "198.51.100.7"},
		{[]byte{127, 0, 0, 1}, "203.0.113.5", "203.0.113.9"},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}, "attacker, 1.1.1.1", "1.1.1.1"},
	}
	for _, s := range seeds {
		f.Add(s.ipb, s.hdr, s.rest)
	}

	f.Fuzz(func(t *testing.T, ipb []byte, hdr string, rest string) {
		ip := ipFromBytes(ipb)
		if ip != nil {
			if err := checkConvergence(ip, core.CanonicalIP); err != nil {
				t.Fatal(err)
			}
		}

		// Build an arbitrary attacker header bundle from the fuzzed strings.
		h := http.Header{}
		h.Set("X-Forwarded-For", hdr)
		h.Add("X-Forwarded-For", rest)
		h.Set("X-Real-IP", hdr)
		h.Set("Forwarded", "for="+hdr)

		// A peer taken from the fuzzed ip (with an ephemeral port) and, separately,
		// a peer taken from the header string (often garbage — exercises the
		// not-an-IP paths).
		peers := []string{}
		if ip != nil {
			peers = append(peers, ip.String()+":443", "["+ip.String()+"]:443")
		}
		peers = append(peers, hdr, rest)

		for _, peer := range peers {
			if err := checkUntrustedHeadersInert(peer, h, realSourceKey); err != nil {
				t.Fatal(err)
			}
			if err := checkTrustedPrependIgnored(peer, rest, realSourceKey); err != nil {
				t.Fatal(err)
			}
		}
	})
}
