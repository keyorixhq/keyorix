// egress_dial_fuzz_test.go — fuzz harness for the actual CONNECTION-TIME SSRF
// enforcement (Dialer.DialContext, dialer.go), as opposed to the pure predicate
// already fuzzed by FuzzIPv4EmbeddingSSRFParity (is this IP private?) and the
// register-time-only admin-DSN checks elsewhere. Before this, dialer.go had 16 of
// 24 mutation-candidate lines with no fuzz coverage at all, and nothing exercised
// resolveValidated -> pin -> dial end to end.
//
// Dialer's Resolve and Dial fields are already plain, overridable struct fields
// (see dialer.go's doc comment) — no production code change was needed to make
// this fuzzable.
//
// The fake Dial below deliberately does NOT just record the address it was
// handed: if that address is a literal IP (the only thing a correct DialContext
// ever passes to Dial, per dialer.go:98), it is recorded as-is. If it is instead
// a hostname — which only happens if DialContext is broken and forwards the
// original host instead of the validated, pinned IP — the fake Dial performs its
// OWN independent "DNS lookup" by calling the same fake resolver a second time,
// exactly mirroring what a real net.Dialer does with no SSRF awareness at all.
// This reproduces the DNS-rebinding attack class end to end without needing a
// separate hand-written red-proof mutation for the rebinding oracle: any fuzz
// input where round 2's answer differs from round 1's (and round 2 contains a
// disallowed address) IS a rebinding attempt, and the harness catches it
// naturally if DialContext ever hands a hostname to Dial.
package netutil

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// dialAnswer is one fake-resolved candidate address plus an INDEPENDENTLY
// computed "should this be treated as private" verdict. wantPrivate is derived
// directly from the raw octets/encoding kind by isRawV4Private below — never by
// calling IsPrivateOrLinkLocal (the function under test) — so a bug that makes
// IsPrivateOrLinkLocal itself wrong (e.g. an over-broad or under-broad NAT64
// rule) cannot also corrupt this harness's own expectation of what "should" have
// happened. Oracle (a) still deliberately calls the real IsPrivateOrLinkLocal
// directly on the dialed address (that IS the policy under test for the
// no-SSRF-dial invariant) — only the (d) over/under-block regression check needs
// this independent ground truth, for exactly the same reason the PAT lifecycle
// harness stopped deriving its "expected restriction" via patRestrictionFrom.
type dialAnswer struct {
	ip          net.IP
	wantPrivate bool
}

// isRawV4Private independently re-implements just the IPv4 ranges
// privateNetworkCIDRs blocks (dialer.go:169-186), by raw octet arithmetic, with
// no call into netutil's own blocklist machinery.
func isRawV4Private(a, b, c, d byte) bool {
	switch {
	case a == 10: // RFC-1918
		return true
	case a == 172 && b >= 16 && b <= 31: // RFC-1918
		return true
	case a == 192 && b == 168: // RFC-1918
		return true
	case a == 127: // loopback
		return true
	case a == 0: // RFC 1122 "this network" -- treated as loopback by many kernels
		return true
	case a == 169 && b == 254: // link-local / cloud IMDS
		return true
	case a == 100 && b >= 64 && b <= 127: // RFC 6598 shared address space
		return true
	}
	return false
}

// decodeAnswer builds one candidate resolved address in one of 7 encodings,
// mirroring FuzzIPv4EmbeddingSSRFParity's encoding builders plus a few
// IPv6-native shapes (ULA-private, link-local, and a "public" IPv6
// documentation-range address), paired with its independently-derived
// wantPrivate verdict.
func decodeAnswer(encKind, a, b, c, d byte) dialAnswer {
	v4Private := isRawV4Private(a, b, c, d)
	switch encKind % 7 {
	case 0: // raw IPv4
		return dialAnswer{net.IPv4(a, b, c, d), v4Private}
	case 1: // IPv4-mapped IPv6
		return dialAnswer{net.ParseIP(fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d)), v4Private}
	case 2: // NAT64 well-known (RFC 6052)
		ip := make(net.IP, net.IPv6len)
		copy(ip, nat64WellKnownPrefix.IP)
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		return dialAnswer{ip, v4Private}
	case 3: // deprecated IPv4-compatible (::a.b.c.d)
		ip := make(net.IP, net.IPv6len)
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		return dialAnswer{ip, v4Private}
	case 4: // IPv6 unique-local (private, unconditionally)
		return dialAnswer{net.ParseIP(fmt.Sprintf("fc00::%02x%02x:%02x%02x", a, b, c, d)), true}
	case 5: // IPv6 link-local (private, unconditionally)
		return dialAnswer{net.ParseIP(fmt.Sprintf("fe80::%02x%02x:%02x%02x", a, b, c, d)), true}
	case 6: // IPv6 "public" documentation range (never private)
		return dialAnswer{net.ParseIP(fmt.Sprintf("2001:db8::%02x%02x:%02x%02x", a, b, c, d)), false}
	}
	return dialAnswer{}
}

// decodeRounds decodes program into a bounded sequence of resolver "rounds" — each
// round is the answer set one call to the fake resolver returns. Round 0 is what a
// correct DialContext ever sees or validates against; a later round only comes
// into play if the fake Dial is ever handed a hostname (see the file doc comment),
// which models a changed DNS answer between validation and connect — i.e. rebinding.
func decodeRounds(program []byte) [][]dialAnswer {
	const maxRounds, maxPerRound = 3, 4
	rounds := [][]dialAnswer{{}}
	i := 0
	for i+5 < len(program) && len(rounds) <= maxRounds {
		marker := program[i]
		encKind, a, b, c, d := program[i+1], program[i+2], program[i+3], program[i+4], program[i+5]
		i += 6
		if marker%5 == 0 && len(rounds[len(rounds)-1]) > 0 && len(rounds) < maxRounds {
			rounds = append(rounds, []dialAnswer{})
		}
		ans := decodeAnswer(encKind, a, b, c, d)
		if ans.ip != nil && len(rounds[len(rounds)-1]) < maxPerRound {
			rounds[len(rounds)-1] = append(rounds[len(rounds)-1], ans)
		}
	}
	return rounds
}

func ipInRound(ip net.IP, round []dialAnswer) bool {
	for _, r := range round {
		if r.ip.Equal(ip) {
			return true
		}
	}
	return false
}

// roundAllAllowed reports whether every answer in round is expected-public by
// the INDEPENDENT ground truth (dialAnswer.wantPrivate), never by calling
// IsPrivateOrLinkLocal — see dialAnswer's doc comment for why.
func roundAllAllowed(round []dialAnswer) bool {
	for _, a := range round {
		if a.wantPrivate {
			return false
		}
	}
	return true
}

// FuzzEgressDialEnforcement drives Dialer.DialContext with a fake resolver
// (fuzzer-controlled answer rounds, spanning raw/NAT64/mapped/compat/ULA/
// link-local encodings) and a fake dial layer that records the address actually
// connected to, then asserts:
//
//	(a) no connection is ever made to an address IsPrivateOrLinkLocal calls
//	    private, whatever the resolver sequence — asserted on the ACTUALLY
//	    DIALED address, not the returned error.
//	(b) consistency: the dialed IP is always a member of the FIRST resolved
//	    round — no second, independent (and unvalidated) resolution slips in
//	    between validation and connect.
//	(c) fail-closed on a malformed address, a resolver error, or an empty
//	    answer set: DialContext must return an error AND Dial must never be
//	    invoked.
//	(d) an all-public/all-allowed first round must always succeed — guards
//	    against an over-broad regression (e.g. blocking the whole NAT64 prefix
//	    instead of decoding it, as very nearly happened in #1937).
func FuzzEgressDialEnforcement(f *testing.F) {
	f.Add("example.internal", uint16(443), []byte{0, 0, 8, 8, 8, 8}, false, false)                           // public v4 -> succeed
	f.Add("example.internal", uint16(443), []byte{0, 0, 169, 254, 169, 254}, false, false)                   // private (IMDS) -> refuse
	f.Add("example.internal", uint16(443), []byte{0, 2, 8, 8, 8, 8}, false, false)                           // NAT64-encoded public -> succeed (#1937 regression guard)
	f.Add("example.internal", uint16(443), []byte{0, 2, 169, 254, 169, 254}, false, false)                   // NAT64-encoded private -> refuse
	f.Add("example.internal", uint16(443), []byte{0, 0, 8, 8, 8, 8, 5, 0, 169, 254, 169, 254}, false, false) // 2 rounds, round0 public / round1 private (rebinding shape)
	f.Add("example.internal", uint16(443), []byte{}, false, false)                                           // no answers -> fail closed
	f.Add("example.internal", uint16(443), []byte{0, 0, 8, 8, 8, 8}, true, false)                            // resolver error -> fail closed
	f.Add("no-port-host", uint16(0), []byte{0, 0, 8, 8, 8, 8}, false, true)                                  // malformed addr -> fail closed
	f.Add("10.0.0.5", uint16(443), []byte{}, false, false)                                                   // literal private IP host -> refuse, no resolve

	f.Fuzz(func(t *testing.T, host string, port uint16, program []byte, resolveErr, malformed bool) {
		rounds := decodeRounds(program)
		resolveCalls := 0

		fakeResolve := func(_ context.Context, _ string) ([]net.IPAddr, error) {
			resolveCalls++
			if resolveErr {
				return nil, fmt.Errorf("fuzz: forced resolve error")
			}
			idx := resolveCalls - 1
			if idx >= len(rounds) {
				idx = len(rounds) - 1
			}
			if idx < 0 || len(rounds[idx]) == 0 {
				return nil, nil
			}
			round := rounds[idx]
			addrs := make([]net.IPAddr, len(round))
			for i, a := range round {
				addrs[i] = net.IPAddr{IP: a.ip}
			}
			return addrs, nil
		}

		var dialCount int
		var dialedAddr string
		fakeDial := func(ctx context.Context, _ string, addr string) (net.Conn, error) {
			dialCount++
			dialedAddr = addr
			h, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if net.ParseIP(h) != nil {
				return nil, nil // literal IP: what a correct DialContext always hands us
			}
			// See file doc comment: a hostname here means DialContext is broken.
			// Reproduce what a real, SSRF-unaware net.Dialer would actually do.
			addrs2, err2 := fakeResolve(ctx, h)
			if err2 != nil || len(addrs2) == 0 {
				return nil, fmt.Errorf("fuzz: second-look resolve failed")
			}
			dialedAddr = net.JoinHostPort(addrs2[0].IP.String(), "0")
			return nil, nil
		}

		d := Dialer{Disallow: IsPrivateOrLinkLocal, Resolve: fakeResolve, Dial: fakeDial}

		var addr string
		if malformed {
			addr = host // no port at all -> net.SplitHostPort must reject this
		} else {
			addr = net.JoinHostPort(host, fmt.Sprint(port))
		}
		// Derived from what DialContext itself will actually split addr into,
		// not from the raw host parameter: when malformed is set, addr is the
		// unwrapped fuzz string, so a fuzzer-chosen host that happens to
		// contain its own "ip:port" shape (e.g. "0.0.0.0:0") makes
		// net.SplitHostPort succeed despite malformed's intent, and
		// DialContext then treats the SPLIT host as the literal-IP target —
		// not the untouched, colon-containing outer host string. Recomputing
		// hostIsLiteral from the raw host in that case would wrongly say
		// "not literal" and send this assertion down the rebinding-check
		// branch for an address that was never resolved at all, producing a
		// false REBINDING failure independent of DialContext's own behavior.
		splitHost := host
		if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			splitHost = h
		}
		hostIsLiteral := net.ParseIP(splitHost) != nil

		conn, err := d.DialContext(context.Background(), "tcp", addr)
		_ = conn

		if err != nil {
			// Classify which of DialContext's OWN distinct failure branches fired, by
			// its distinguishing error text (dialer.go:82,124,128,135,138,144) — more
			// robust than trying to independently predict from host/program content
			// whether e.g. net.SplitHostPort will reject a fuzzer-mangled host string;
			// that can fail even when the `malformed` flag wasn't set.
			addrParseFailure := strings.Contains(err.Error(), "invalid dial address")
			resolveFailure := strings.Contains(err.Error(), "resolve ") && !strings.Contains(err.Error(), "did not resolve to any address")
			noAnswersFailure := strings.Contains(err.Error(), "did not resolve to any address")
			// #1948: an empty/whitespace-only host is refused before any lookup —
			// fires with dialCount==0 exactly like the other three, and for a
			// fuzzer-chosen empty host, rounds[0] (never populated, since resolve
			// is never called) is vacuously "all allowed" by roundAllAllowed. Without
			// this branch that vacuous truth misclassifies the refusal as an
			// OVER-BLOCK regression instead of the correct, intentional fail-closed
			// guard it actually is.
			emptyHostFailure := strings.Contains(err.Error(), "refusing to dial an empty host")

			// (c) fail-closed: none of these four should ever reach Dial.
			if addrParseFailure || resolveFailure || noAnswersFailure || emptyHostFailure {
				if dialCount != 0 {
					t.Fatalf("FAIL-CLOSED VIOLATION: DialContext errored (%v) but still invoked Dial %d time(s), addr=%q", err, dialCount, dialedAddr)
				}
				return
			}
			// Any other error means resolveValidated refused a disallowed address —
			// that's the guard doing its job, UNLESS round0 was entirely allowed by
			// the INDEPENDENT ground truth, in which case this is an over-block
			// regression — (d). (The literal-IP-host path has no independent ground
			// truth to check against here — the fuzzer's free-form host string isn't
			// tagged with an expected verdict the way a decoded round answer is — so
			// it's covered only by the universal SSRF/no-dial-after-error checks
			// below, not by this over-block assertion.)
			if !hostIsLiteral && roundAllAllowed(rounds[0]) {
				t.Fatalf("OVER-BLOCK: DialContext refused an all-public/allowed round %v: %v", rounds[0], err)
			}
			if dialCount != 0 {
				t.Fatalf("DIAL AFTER ERROR: DialContext returned error %v yet Dial was invoked (addr=%q)", err, dialedAddr)
			}
			return
		}

		// Success path.
		if dialCount == 0 {
			t.Fatalf("DialContext succeeded with nil error but never invoked Dial")
		}
		if dialCount > 1 {
			t.Fatalf("MULTIPLE DIALS: DialContext caused %d dial attempts for a single call (addr=%q)", dialCount, dialedAddr)
		}
		dialedHost, _, splitErr := net.SplitHostPort(dialedAddr)
		if splitErr != nil {
			t.Fatalf("captured dialed address %q does not split into host:port: %v", dialedAddr, splitErr)
		}
		dialedIP := net.ParseIP(dialedHost)
		if dialedIP == nil {
			t.Fatalf("captured dialed address %q has a non-IP-literal host %q", dialedAddr, dialedHost)
		}

		// (a) no dial to a blocklisted address, whatever the resolver did.
		if IsPrivateOrLinkLocal(dialedIP) {
			t.Fatalf("SSRF VIOLATION: dialed disallowed address %s (raw addr=%q)", dialedIP, dialedAddr)
		}

		// (b) consistency: the dialed IP must come from round 0 — the only round a
		// correct DialContext ever resolves or validates against.
		if !hostIsLiteral {
			if !ipInRound(dialedIP, rounds[0]) {
				t.Fatalf("REBINDING: dialed %s, which is not a member of the first resolved round %v — DialContext used a later/unvalidated resolution", dialedIP, rounds[0])
			}
		} else if !dialedIP.Equal(net.ParseIP(splitHost)) {
			t.Fatalf("literal-IP host %q dialed a different address %s", splitHost, dialedIP)
		}
	})
}
