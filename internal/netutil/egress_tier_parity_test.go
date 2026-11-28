// egress_tier_parity_test.go — V7-EGRESS-PARITY-1.
//
// ONE differential harness that drives every IP-class egress guard in the codebase
// through the SAME probe table and the SAME real entry point (netutil.Dialer), so a
// guard that silently drifts from the others fails a test instead of passing.
//
// WHY A SINGLE CROSS-GUARD HARNESS (and not just the per-site V7-GAP-1 targets).
// The per-site transport targets (FuzzConnectVaultTransportEgressParity, ...) each prove
// ONE site wires the netutil predicate it claims, by comparing that site's real
// DialContext to the independent egressref reference. They do not ask the cross-guard
// question this harness owns: does every guard agree with the strict reference EXCEPT at a
// documented, STILL-LIVE policy difference? In particular the existing
// evidencesink.TestDocumentedExceptionsAreComplete checks only that each table row has
// non-empty fields — never that the row still corresponds to a real divergence. O3 below
// closes that: a row that no longer differs fails the test (no stale rows).
//
// THE GUARDS. Every outbound site that refuses a destination BY ITS IP CLASS does so
// through one of three netutil tier predicates, wired into a netutil.Dialer:
//
//	reference / "private" tier  netutil.IsPrivateOrLinkLocal              S16, S21, S24
//	"link-local" tier           netutil.IsLinkLocal                       S09, S11-S14, S18
//	"webhook" tier              netutil.IsPrivateOrLinkLocalExceptLoopback S01, S03, S05, S07
//	SIEM forwarder              siem.DialDisallowed (== webhook tier)     S05
//
// netutil.IsPrivateOrLinkLocal is THE REFERENCE: it is the strictest tier (refuses
// RFC-1918, loopback, 0.0.0.0/8, 169.254/16 IMDS, RFC-6598 CGNAT, IPv6 ULA/link-local, and
// every embedded-IPv4 encoding of all of those). The independent ground truth for "the
// reference refuses this" is egressref.Addr.Private (octet arithmetic, no netutil call), so
// a bug in netutil's own CIDR tables cannot define away the expectation it is checked
// against. The SIEM forwarder is driven through its OWN exported predicate
// (siem.DialDisallowed), so a regression that reintroduced a hand-rolled stdlib classifier
// there (the F1/F2 shape) would diverge from the reference and fail, not hide behind the
// shared predicate.
//
// Guards NOT in this harness, and why (reported, not fuzzed): the pinned-endpoint guard
// (S08) and the operator allow-list guard (S26) do not make a per-address refusal decision,
// so they are not comparable on the IP-class axis. The no-guard sites S10 (finding F2,
// #4738) and S22 (finding F1) have no guard to drive. See the report and
// docs/security/egress-inventory.md.
//
// THE ORACLES (sound directions only):
//
//	O1  a destination the reference refuses (egressref Private) must be refused by every
//	    guard, UNLESS an intentionalDiffs row for that guard licenses the destination class.
//	O2  a divergence (reference refuses, guard permits) with no licensing row is a FINDING.
//	O3  every intentionalDiffs row must be exercised by a live divergence in the fixed seed
//	    corpus; a row that no longer corresponds to a real difference is stale and FAILS.
//	O4  no real network connection is made: the injected Dial records the address it is
//	    asked to connect to and never opens a socket, and the harness asserts it is only
//	    ever handed a validated literal IP (never a hostname, never a rebound address).
//
// A guard being STRICTER than the reference (refuses something the reference permits) is
// impossible for these tiers (private is the strictest) and is asserted as a soundness
// check, not treated as a parity violation.
//
// WHAT THIS HARNESS DOES NOT VERIFY: real DNS resolution, the cgo resolver,
// /etc/hosts/search-domain handling; real TLS handshakes, certificate verification or
// HTTP/2 specifics; an egress proxy taken from the environment (the dial then targets the
// proxy, not the destination); textual-only literal spellings (decimal 2130706433, octal,
// 0x7f000001, trailing dot) — net.ParseIP rejects them all, so every guard falls through to
// hostname resolution identically and they cannot diverge BETWEEN guards on the literal
// path (the rebind test exercises the resolver fall-through instead); the redirect-chain
// CheckRedirect policy, which is an unexported per-package function not reachable
// cross-package without patching production (each package tests its own; the dial-time
// re-validation every redirect hop relies on IS exercised here, because netutil.Dialer
// re-validates on every DialContext call). The pinned-endpoint (S08) and allow-list (S26)
// mechanisms are out of scope as noted above.
//
// Degenerate IPv6 embeddings of 0.0.0.x: an embedding such as the IPv4-compatible ::0.0.0.1
// collides with a distinct special IPv6 address (::1), whose true class differs from the
// octets. isLoopbackClass handles the ::1 case (stdlib loopback); otherwise these forms are
// classified by their real assembled address, and the raw-IPv4 0.0.0.0/8 range is covered by
// its own seed. This mirrors the a==0 skip in evidencesink's FuzzEgressGuardParity.
package netutil_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/audit/siem"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// errRecorded is what the injected base dialer returns instead of opening a socket. A guard
// that PERMITS an address hands it to this dialer, which records it and returns errRecorded;
// a guard that REFUSES returns netutil's own "disallowed address" error first and the base
// dialer is never reached. So "permitted" and "refused" are read without any network I/O.
var errRecorded = errors.New("egressparity: recorded, no real connection made")

// recordingDialer is the O4 seam: it records every address a guard tries to connect to and
// never dials anything. After a sweep the harness asserts every recorded address is a
// literal IP (the pinned, validated one), never a hostname or a second, unvalidated answer.
type recordingDialer struct {
	addrs []string
}

func (r *recordingDialer) dial(_ context.Context, _, addr string) (net.Conn, error) {
	r.addrs = append(r.addrs, addr)
	return nil, errRecorded
}

// assertOnlyLiteralIPs is O4: a guard must only ever dial a literal IP it validated. A
// hostname here would mean the dial re-resolved after validation (the DNS-rebinding hole).
func (r *recordingDialer) assertOnlyLiteralIPs(t *testing.T) {
	t.Helper()
	for _, a := range r.addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			t.Fatalf("O4: recorded dial address %q is not host:port: %v", a, err)
		}
		if net.ParseIP(host) == nil {
			t.Fatalf("O4: guard dialed non-literal host %q — it re-resolved after validation (DNS-rebinding hole)", host)
		}
	}
}

// driveGuard runs addr (a literal, optionally with an IPv6 zone suffix) through a REAL
// netutil.Dialer wired with the guard's predicate and the recording base dialer, and
// returns whether the guard refused it. No network: a permitted address reaches the
// recorder, which returns errRecorded.
func driveGuard(t *testing.T, disallow netutil.IPValidator, rec *recordingDialer, a egressref.Addr, port uint16, zone string) bool {
	t.Helper()
	host := a.IP.String()
	if zone != "" && a.IP.To4() == nil {
		host += "%" + zone
	}
	d := netutil.Dialer{Disallow: disallow, Dial: rec.dial}
	_, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	switch {
	case err == nil:
		t.Fatalf("guard returned a nil error for %s; the recording dialer must never succeed", a)
		return false
	case errors.Is(err, errRecorded):
		return false // permitted: reached the base dialer
	default:
		// netutil.Dialer refuses with "...disallowed address <ip>". Anything else is a
		// harness bug (e.g. a malformed address), surface it rather than guess.
		if !containsDisallowed(err) {
			t.Fatalf("guard returned an unexpected error for %s: %v", a, err)
		}
		return true // refused
	}
}

func containsDisallowed(err error) bool {
	return err != nil && strings.Contains(err.Error(), "disallowed address")
}

// guardUnderTest names a guard and its real predicate. The reference (private tier) is one
// of them, driven as a GREEN control: it must refuse exactly the egressref Private set.
type guardUnderTest struct {
	name        string
	disallow    netutil.IPValidator
	isReference bool
}

func guardsUnderTest() []guardUnderTest {
	return []guardUnderTest{
		{"private", netutil.IsPrivateOrLinkLocal, true},
		{"link-local", netutil.IsLinkLocal, false},
		{"webhook", netutil.IsPrivateOrLinkLocalExceptLoopback, false},
		{"siem", siem.DialDisallowed, false},
	}
}

// intentionalDiff is one row of the INTENTIONAL-DIFFERENCES table: a guard is deliberately
// allowed to PERMIT a destination class the reference refuses. covers(a) reports whether
// this row licenses a divergence on address a — derived from egressref verdicts (octet
// arithmetic), never from netutil, so the table cannot launder a netutil bug into a license.
type intentionalDiff struct {
	guard  string
	class  string
	reason string
	doc    string
	covers func(egressref.Addr) bool
}

// intentionalDiffs is the complete set of deliberate, documented divergences from the strict
// reference. Each is a policy choice stated at the predicate in internal/netutil/dialer.go
// and in the tier table of docs/security/egress-inventory.md. O3 checks every row is still
// live.
var intentionalDiffs = []intentionalDiff{
	{
		guard:  "link-local",
		class:  "private-but-not-link-local: RFC-1918, loopback, 0.0.0.0/8, RFC-6598 CGNAT, IPv6 ULA (incl. fd00:ec2::254), in every embedded encoding",
		reason: "the link-local tier guards egress to operator-configured OIDC issuers and Connect backends, which are on-prem/air-gapped first and legitimately live on internal 10.x/192.168.x/ULA segments; only the universal IMDS endpoint (169.254.169.254 and its encodings, and fe80::/10) must stay unreachable.",
		doc:    "internal/netutil/dialer.go linkLocalCIDRs + IsLinkLocal doc; docs/security/egress-inventory.md tier table (link-local).",
		covers: func(a egressref.Addr) bool { return a.Private && !a.LinkLocal },
	},
	{
		guard:  "webhook",
		class:  "loopback (127.0.0.0/8, ::1, and embedded-IPv4 loopback)",
		reason: "a webhook/notification/evidence receiver is an operator-configured endpoint that may legitimately run on the local host during dev/test, unlike a backend admin DSN which is the deployment's own services; the ONLY difference from the strict tier.",
		doc:    "internal/netutil/dialer.go IsPrivateOrLinkLocalExceptLoopback doc; docs/security/egress-inventory.md tier table (webhook).",
		covers: isLoopbackClass,
	},
	{
		guard:  "siem",
		class:  "loopback (127.0.0.0/8, ::1, and embedded-IPv4 loopback)",
		reason: "the SIEM forwarder is the webhook tier: a Splunk/Datadog/webhook intake may run on the local host in dev/test. This row is distinct from the webhook row so O3 proves siem.DialDisallowed still IS the webhook tier (a drift back to a hand-rolled stdlib classifier — the F1/F2 shape — would stop permitting loopback here or start permitting CGNAT and fail O2).",
		doc:    "internal/audit/siem/forwarder.go isDisallowedIP (== netutil.IsPrivateOrLinkLocalExceptLoopback); docs/security/egress-inventory.md S05.",
		covers: isLoopbackClass,
	},
}

// isLoopbackClass recognises a destination as "loopback" for the webhook/SIEM loopback
// license. It is deliberately the UNION of the octet-derived egressref flag and the standard
// library's net.IP.IsLoopback — NOT netutil's own classification, so it cannot launder a
// netutil bug into a license. The stdlib arm exists only for the degenerate IPv6 forms where
// an embedding of 0.0.0.x collides with a distinct special address: e.g. the IPv4-compatible
// encoding ::0.0.0.1 IS ::1 (real loopback), but egressref derives its Loopback flag from the
// octets 0.0 (not 127) and so reports false. Adding the stdlib arm is strictly additive: it
// only ever extends the license to a destination that genuinely IS loopback, so it can never
// mask a non-loopback private address (which has both arms false and remains a finding).
func isLoopbackClass(a egressref.Addr) bool {
	return a.Loopback || a.IP.IsLoopback()
}

// license returns the row that permits a divergence (reference refuses, guard permits) on a,
// or nil if none does (a finding).
func license(guard string, a egressref.Addr) *intentionalDiff {
	for i := range intentionalDiffs {
		r := &intentionalDiffs[i]
		if r.guard == guard && r.covers(a) {
			return r
		}
	}
	return nil
}

// checkParity drives every guard on a and enforces O1/O2 and the stricter-than-reference
// soundness check. It returns the set of row keys that fired a live divergence, for O3.
func checkParity(t *testing.T, a egressref.Addr, port uint16, zone string) map[string]bool {
	t.Helper()
	fired := map[string]bool{}
	rec := &recordingDialer{}
	refRefuses := a.Private // independent reference verdict
	for _, g := range guardsUnderTest() {
		refused := driveGuard(t, g.disallow, rec, a, port, zone)
		if g.isReference {
			// GREEN control: the reference guard must refuse exactly the egressref Private set.
			if refused != refRefuses {
				t.Fatalf("reference guard (private tier) disagrees with egressref on %s: netutil refused=%v, egressref.Private=%v — a netutil CIDR/encoding bug or an egressref bug, either way a finding", a, refused, refRefuses)
			}
			continue
		}
		switch {
		case refRefuses && !refused:
			// O1/O2: a divergence. It must be licensed.
			row := license(g.name, a)
			if row == nil {
				t.Fatalf("O2 FINDING: guard %q PERMITS %s, which the reference refuses, and no INTENTIONAL-DIFFERENCES row licenses it", g.name, a)
			}
			fired[g.name+"|"+row.class] = true
		case !refRefuses && refused:
			// Stricter than the strictest reference: impossible for these tiers.
			t.Fatalf("soundness: guard %q REFUSES %s, which the reference permits — no tier is stricter than the private reference", g.name, a)
		}
	}
	rec.assertOnlyLiteralIPs(t) // O4
	return fired
}

// fixedSeeds is the deterministic probe corpus. It must contain at least one address that
// exercises each intentionalDiffs row (so O3 is meaningful) and at least one IMDS address
// that NO row licenses (so O1 has teeth). a,b,c,d are octets; kind selects the egressref
// encoding; zone adds an IPv6 zone id.
var fixedSeeds = []struct {
	kind, a, b, c, d byte
	port             uint16
	zone             string
}{
	{0, 169, 254, 169, 254, 80, ""},  // IMDS raw — refused by all, licensed by none
	{1, 169, 254, 169, 254, 443, ""}, // IMDS IPv4-mapped
	{2, 169, 254, 169, 254, 443, ""}, // IMDS NAT64 well-known
	{3, 169, 254, 169, 254, 443, ""}, // IMDS NAT64 local-use
	{4, 169, 254, 169, 254, 443, ""}, // IMDS IPv4-compatible
	{5, 169, 254, 169, 254, 443, ""}, // IMDS 6to4
	{6, 169, 254, 169, 254, 443, ""}, // IMDS Teredo
	{7, 0, 0, 0, 1, 443, "eth0"},     // fe80:: native link-local with a zone id
	{0, 0, 0, 0, 5, 443, ""},         // 0.0.0.0/8 "this network" — licensed for link-local only
	{0, 10, 0, 0, 5, 443, ""},        // RFC-1918 — licensed for link-local only
	{2, 10, 0, 0, 5, 443, ""},        // RFC-1918 via NAT64 — same, in an encoding
	{0, 192, 168, 1, 1, 80, ""},      // RFC-1918 192.168
	{0, 172, 16, 0, 1, 80, ""},       // RFC-1918 172.16
	{0, 100, 64, 0, 1, 80, ""},       // CGNAT (RFC 6598) — licensed for link-local only
	{0, 100, 100, 100, 200, 80, ""},  // Alibaba IMDS, inside CGNAT
	{0, 127, 0, 0, 1, 443, ""},       // loopback — licensed for webhook+siem (and link-local)
	{4, 127, 0, 0, 1, 443, ""},       // loopback via IPv4-compatible encoding
	{8, 0, 0, 0, 0, 80, ""},          // fd00:ec2::254 (AWS IPv6 IMDS), ULA — licensed for link-local
	{8, 0, 0, 0, 5, 80, ""},          // generic ULA fd00:ec2::5
	{0, 8, 8, 8, 8, 443, ""},         // public — permitted by all
	{2, 8, 8, 8, 8, 443, ""},         // public via NAT64 (#1937) — permitted by all
	{9, 1, 2, 3, 4, 443, ""},         // public IPv6 — permitted by all
}

// TestEgressTierParity_FixedSeeds enforces O1/O2/O4 across the deterministic corpus and
// collects which rows fired, then TestEgressTierParity_NoStaleRows (O3) asserts every row
// fired. They share seedFirings so O3 sees exactly what the parity sweep saw.
func TestEgressTierParity_FixedSeeds(t *testing.T) {
	fired := seedFirings(t)
	if len(fired) == 0 {
		t.Fatal("no divergence fired across the whole seed corpus; the harness is not exercising any guard difference")
	}
}

// seedFirings runs the parity sweep over the fixed seeds and returns the union of row keys
// that fired a live divergence.
func seedFirings(t *testing.T) map[string]bool {
	t.Helper()
	all := map[string]bool{}
	for _, s := range fixedSeeds {
		a := egressref.Decode(s.kind, s.a, s.b, s.c, s.d)
		for k := range checkParity(t, a, s.port, s.zone) {
			all[k] = true
		}
	}
	return all
}

// TestEgressTierParity_NoStaleRows is O3: every INTENTIONAL-DIFFERENCES row must correspond
// to a divergence that actually occurs in the seed corpus. A row that no longer differs (the
// guard was tightened to match the reference, or the class became unreachable) fails here —
// so the table cannot accumulate stale allowances that quietly license nothing.
func TestEgressTierParity_NoStaleRows(t *testing.T) {
	fired := seedFirings(t)
	for _, r := range intentionalDiffs {
		key := r.guard + "|" + r.class
		if !fired[key] {
			t.Fatalf("O3 STALE ROW: intentional-difference row %q / %q was never exercised by a live divergence — remove it or restore the seed that proves it", r.guard, r.class)
		}
	}
	// And the reverse: every fired divergence was licensed (already enforced per-address in
	// checkParity via the O2 Fatalf; this is the table-level restatement).
	if len(fired) == 0 {
		t.Fatal("no rows fired; see TestEgressTierParity_FixedSeeds")
	}
}

// TestEgressTierParity_TableWellFormed keeps each row honest: a row must name a guard that
// is actually under test, and fill every field. (O3 proves it is live; this proves it is
// not a bare allowance.)
func TestEgressTierParity_TableWellFormed(t *testing.T) {
	names := map[string]bool{}
	for _, g := range guardsUnderTest() {
		names[g.name] = true
	}
	if len(intentionalDiffs) == 0 {
		t.Fatal("intentionalDiffs is empty; the loopback and on-prem exceptions must stay documented")
	}
	for i, r := range intentionalDiffs {
		if r.guard == "" || r.class == "" || r.reason == "" || r.doc == "" || r.covers == nil {
			t.Errorf("intentionalDiffs[%d] has an empty field: %+v", i, r)
		}
		if !names[r.guard] {
			t.Errorf("intentionalDiffs[%d] names guard %q, which is not under test", i, r.guard)
		}
	}
}

// FuzzEgressTierParity is the fuzz form of O1/O2/O4: for every fuzzed destination in every
// encoding it drives all guards and fails on an unlicensed divergence. It does not assert O3
// (a single fuzz input cannot exercise every row); the fixed-seed tests above own O3.
func FuzzEgressTierParity(f *testing.F) {
	for _, s := range fixedSeeds {
		f.Add(s.kind, s.a, s.b, s.c, s.d, s.port, s.zone != "")
	}
	f.Fuzz(func(t *testing.T, kind, a, b, c, d byte, port uint16, zone bool) {
		z := ""
		if zone {
			z = "eth0"
		}
		checkParity(t, egressref.Decode(kind, a, b, c, d), port, z)
	})
}

// --- Rebinding / "validate the name, dial the IP" (O4 at the resolver seam) --------------
//
// The literal-address sweep above cannot exercise the DNS-rebinding property, because it
// never resolves a name. This test drives a HOSTNAME through the real netutil.Dialer with an
// injected resolver whose answer set is a fuzzed pair of encodings, and checks the two
// properties every link-local/webhook/private site relies on:
//
//   - the WHOLE first answer set is refused when the tier refuses ANY address in it (a mixed
//     public/private answer must not slip through because one answer passed first);
//   - a permitted set is dialed at the validated literal IP, never the hostname again (O4).
//
// It does NOT verify a real DNS server, the cgo resolver, /etc/hosts, or an egress proxy.
func TestEgressTierParity_RebindAnswerSetValidated(t *testing.T) {
	type pair struct{ k1, a1, b1, c1, d1, k2, a2, b2, c2, d2 byte }
	seeds := []pair{
		{9, 1, 2, 3, 4, 0, 169, 254, 169, 254}, // public first, IMDS second — mixed, must refuse
		{2, 8, 8, 8, 8, 4, 169, 254, 169, 254}, // public-via-NAT64 first, IMDS-compat second
		{9, 1, 2, 3, 4, 9, 93, 184, 216, 34},   // both public — permitted, dial pinned literal
	}
	for _, g := range guardsUnderTest() {
		for _, s := range seeds {
			a1 := egressref.Decode(s.k1, s.a1, s.b1, s.c1, s.d1)
			a2 := egressref.Decode(s.k2, s.a2, s.b2, s.c2, s.d2)
			rec := &recordingDialer{}
			resolve := func(_ context.Context, _ string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: a1.IP}, {IP: a2.IP}}, nil
			}
			d := netutil.Dialer{Disallow: g.disallow, Resolve: resolve, Dial: rec.dial}
			_, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("rebind.example.test", "443"))

			// Reference-independent expectation: the tier refuses the whole set iff it
			// refuses either member, computed from the guard's own predicate on each literal
			// (which the literal sweep already proved matches egressref).
			wantRefuse := g.disallow(a1.IP) || g.disallow(a2.IP)
			refused := containsDisallowed(err)
			if wantRefuse && !refused {
				t.Fatalf("guard %q: BYPASS of mixed answer set [%s %s]: dial returned %v", g.name, a1, a2, err)
			}
			if !wantRefuse && !refused {
				// permitted: must have dialed the validated literal, never the hostname.
				rec.assertOnlyLiteralIPs(t)
				if len(rec.addrs) != 1 {
					t.Fatalf("guard %q: permitted set should dial exactly once, dialed %d times", g.name, len(rec.addrs))
				}
			}
		}
	}
}

// compile-time assurance the shared predicate shape matches netutil.IPValidator.
var _ = []netutil.IPValidator{
	netutil.IsPrivateOrLinkLocal,
	netutil.IsLinkLocal,
	netutil.IsPrivateOrLinkLocalExceptLoopback,
	siem.DialDisallowed,
}
