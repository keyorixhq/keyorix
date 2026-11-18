// source_key_equivalence_redgreen_test.go — red/green proofs for the three RL1
// source-key oracles (FuzzSourceRateLimitKeyEquivalence). Each oracle is fed the
// REAL pipeline (must return nil = green) and a deliberately-broken one that
// reintroduces a real bypass class (must return an error = red). No production
// code is edited; the broken pipelines live only in this test.
package middleware

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

// --- broken implementations (each reintroduces one real defect class) ---

// canonNoPortStrip forgets to strip the :port — so a reconnecting client's fresh
// ephemeral port lands every attempt in a different bucket (the #G20 defect).
func canonNoPortStrip(addr string) string { return addr }

// keyTrustsHeadersAlways honours X-Forwarded-For regardless of whether the peer
// is a trusted proxy — the chi middleware.RealIP spoof the ClientIP middleware
// exists to replace.
func keyTrustsHeadersAlways(peer string, _ []*net.IPNet, h http.Header) string {
	if xff := strings.TrimSpace(h.Get("X-Forwarded-For")); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		return canonIP(first)
	}
	return canonIP(peer)
}

// keyLeftmostXFF trusts the peer correctly but, behind a trusted proxy, takes the
// LEFTMOST XFF hop (classic client-spoofable parse) instead of walking right→left.
func keyLeftmostXFF(peer string, trusted []*net.IPNet, h http.Header) string {
	r := &http.Request{RemoteAddr: peer, Header: h}
	if peerIsTrustedProxy(r, trusted) {
		if xff := strings.TrimSpace(h.Get("X-Forwarded-For")); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); net.ParseIP(first) != nil {
				return canonIP(first)
			}
		}
	}
	return canonIP(peer)
}

// canonIP is core.CanonicalIP (reached via the real pipeline with no proxy), used
// by the broken impls above. It is the REAL canonicaliser; only the trust/port
// logic around it in those impls is broken.
func canonIP(addr string) string { return realSourceKey(addr, nil, http.Header{}) }

// --- oracle 1: convergence ---

func TestRedGreen_Convergence(t *testing.T) {
	// A v6 address with a compressible run and an ephemeral port in one form.
	ip := net.ParseIP("2001:db8::1")
	if ip == nil {
		t.Fatal("seed IP did not parse")
	}
	// GREEN: real CanonicalIP collapses every equivalent form.
	if err := checkConvergence(ip, realCanon); err != nil {
		t.Fatalf("GREEN failed: real CanonicalIP should converge: %v", err)
	}
	// RED: the no-port-strip canon leaves the ":54321"/bracket forms distinct.
	if err := checkConvergence(ip, canonNoPortStrip); err == nil {
		t.Fatal("RED failed: a canon that does not strip the port must diverge")
	}
}

// realCanon is core.CanonicalIP with the production signature for checkConvergence.
func realCanon(addr string) string {
	return canonIP(addr)
}

// --- oracle 2: untrusted peer ⇒ headers inert ---

func TestRedGreen_UntrustedHeadersInert(t *testing.T) {
	peer := "198.51.100.23:5555" // a directly-connected client, no proxy in front
	h := http.Header{}
	h.Set("X-Forwarded-For", "203.0.113.200") // attacker claims a victim source
	// GREEN: the real pipeline ignores the header when no proxy is trusted.
	if err := checkUntrustedHeadersInert(peer, h, realSourceKey); err != nil {
		t.Fatalf("GREEN failed: real pipeline must ignore untrusted headers: %v", err)
	}
	// RED: a pipeline that always trusts XFF lets the header move the key.
	if err := checkUntrustedHeadersInert(peer, h, keyTrustsHeadersAlways); err == nil {
		t.Fatal("RED failed: a header-trusting pipeline must let the key move off the peer")
	}
}

// --- oracle 3: trusted peer ⇒ leftmost prepend ignored ---

func TestRedGreen_TrustedPrependIgnored(t *testing.T) {
	peer := "203.0.113.7:443" // this IS the trusted proxy (trusted set built from it)
	spoof := "6.6.6.6"        // attacker-prepended hop, distinct from the real client
	// GREEN: real pipeline walks right→left, so a left-prepended spoof is ignored.
	if err := checkTrustedPrependIgnored(peer, spoof, realSourceKey); err != nil {
		t.Fatalf("GREEN failed: real pipeline must ignore a left-prepended spoof: %v", err)
	}
	// RED: the leftmost-XFF pipeline returns the prepended attacker hop.
	if err := checkTrustedPrependIgnored(peer, spoof, keyLeftmostXFF); err == nil {
		t.Fatal("RED failed: a leftmost-XFF pipeline must change the key when a spoof is prepended")
	}
}
