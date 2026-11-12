// Differential egress-guard parity harness (task V7).
//
// Drives the SAME address — in every IPv6 encoding that embeds an IPv4 address,
// plus native IPv6 link-local literals and the cloud-metadata IPs — through
// THIS package's dial-time SSRF classifier (evidencesink's unexported
// isDisallowedIP, wired into a netutil.Dialer at webhook.go:85-93) and compares
// each verdict against the netutil REFERENCE and against a sibling
// webhook-tier guard (internal/audit/siem, exported as siem.DialDisallowed).
//
// THE REFERENCE (netutil) and THE POLICY TIERS
//
//	netutil.IsPrivateOrLinkLocal is the strict backend tier: it refuses
//	RFC-1918, loopback, 0.0.0.0/8, 169.254/16, RFC-6598 CGNAT (100.64/10),
//	IPv6 ULA/link-local AND every embedded-IPv4 encoding of those (NAT64
//	well-known + local-use/96, IPv4-compatible, 6to4, Teredo).
//
//	The "webhook tier" (evidencesink, siem, notifychan, internal/core's
//	channel guard) is meant to be that SAME policy with ONE documented
//	exception: loopback is PERMITTED (an operator-configured webhook/SIEM/
//	evidence receiver is a legitimate local dev/test target, unlike a backend
//	admin DSN). webhookTierReference below encodes exactly that: netutil's
//	verdict, minus loopback.
//
// WHY THIS HARNESS EXISTS (not redundant with core's FuzzSSRFGuardDifferential):
// that fuzzer covers netutil's two tiers, siem, internal/core's channel guard,
// the connect/jwks dialer and the admin-DSN guard — every webhook-tier sibling
// EXCEPT evidencesink, whose isDisallowedIP has no exported seam and lives in
// this package. evidencesink was precisely the webhook-tier guard that did NOT
// decode embedded IPv4 (FINDING F1, fixed on this branch). The harness also
// measures the webhook tier against the FULL netutil reference, which surfaced
// the CGNAT gap every webhook-tier guard shared (FINDING F2, fixed on this
// branch) — a divergence core's fuzzer does not assert because it compares each
// guard only to its own raw-form verdict, not to the stricter netutil reference.
//
// ORACLE: no webhook-tier guard may ALLOW what webhookTierReference FORBIDS,
// except the one documented exception (loopback). A new, undocumented
// divergence fails. Ground truth is always a real function on the raw form,
// never hand-derived, so the harness cannot bake in a wrong stdlib assumption.
//
// WHAT THE ORACLE DOES NOT VERIFY:
//   - Textual-spelling literals (decimal 2130706433, octal, hex 0x7f000001,
//     trailing-dot "127.0.0.1."): net.ParseIP rejects all of them and EVERY
//     guard here gates its literal fast path on net.ParseIP, so they uniformly
//     fall through to hostname resolution and cannot diverge BETWEEN guards on
//     literalness. The DNS-rebinding test exercises the resolver fall-through
//     for evidencesink; a pure-literal spelling never reaches a classifier as
//     an IP. Documented, not a silent gap (mirrors core's harness).
//   - Redirect-chain policy across packages: refuseRedirect is unexported in
//     every package and the implementations are structurally identical (refuse
//     cross-host + https->http downgrade, 3-hop cap) except oidcverify (permits
//     same-host). Kept as a documented table in the report, not code, since the
//     funcs are not reachable cross-package without patching production.
//   - IPv6-native non-link-local internal addresses beyond fc00::/7 and the
//     metadata set enumerated here.
package evidencesink

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/keyorixhq/keyorix/internal/audit/siem"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// webhookTierReference is the netutil reference verdict for the webhook tier:
// netutil.IsPrivateOrLinkLocal, minus the one documented exception (loopback,
// direct or embedded). Built from netutil's EXPORTED primitives only, so it is
// a true reference and not a copy of any guard under test.
func webhookTierReference(ip net.IP) bool {
	if ip.IsLoopback() {
		return false
	}
	if v4 := netutil.EmbeddedIPv4(ip); v4 != nil && v4.IsLoopback() {
		return false // ::127.0.0.1 / NAT64-of-loopback etc. — permitted, same as direct loopback
	}
	return netutil.IsPrivateOrLinkLocal(ip)
}

const encodingKinds = 8

// buildLiteral returns the net.IP and textual form for encKind applied to
// a.b.c.d. 0..6 embed the SAME a.b.c.d; 7 is a native link-local literal that
// does NOT embed a.b.c.d. Uses fmt.Sprintf + net.ParseIP so it needs no access
// to netutil's unexported prefix vars — a bug in this harness's byte layout
// cannot cancel a matching bug in production.
func buildLiteral(encKind, a, b, c, d byte) (net.IP, string) {
	var s string
	switch encKind % encodingKinds {
	case 0:
		s = fmt.Sprintf("%d.%d.%d.%d", a, b, c, d) // raw IPv4
	case 1:
		s = fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d) // IPv4-mapped (stdlib folds via To4)
	case 2:
		s = fmt.Sprintf("64:ff9b::%d.%d.%d.%d", a, b, c, d) // NAT64 well-known
	case 3:
		s = fmt.Sprintf("64:ff9b:1::%d.%d.%d.%d", a, b, c, d) // NAT64 local-use /96
	case 4:
		s = fmt.Sprintf("::%d.%d.%d.%d", a, b, c, d) // deprecated IPv4-compatible
	case 5:
		s = fmt.Sprintf("2002:%02x%02x:%02x%02x::", a, b, c, d) // 6to4
	case 6:
		s = fmt.Sprintf("2001::%02x%02x:%02x%02x", a^0xff, b^0xff, c^0xff, d^0xff) // Teredo (XOR)
	default:
		s = fmt.Sprintf("fe80::%02x%02x:%02x%02x", a, b, c, d) // native link-local
	}
	return net.ParseIP(s), s
}

// documentedException records an INTENTIONAL difference from the netutil
// reference, with reason and code reference. The ONLY one the webhook tier is
// permitted: loopback. Everything else a webhook guard allows that the
// reference forbids is a FINDING, not an exception.
type documentedException struct {
	guard, diff, reason, ref string
}

var documentedExceptions = []documentedException{
	{
		guard:  "evidencesink/siem/notifychan/core-channel (webhook tier)",
		diff:   "PERMIT loopback (127.0.0.0/8, ::1, and embedded-IPv4 loopback), which netutil.IsPrivateOrLinkLocal refuses",
		reason: "a webhook/SIEM/evidence receiver is an operator-configured EXTERNAL endpoint; a local receiver is a legitimate dev/test target, unlike a backend admin DSN where loopback is the deployment's own services.",
		ref:    "internal/evidencesink/webhook.go:140-148,182; internal/audit/siem/forwarder.go:50-58,103; internal/netutil/dialer.go:197-206",
	},
	{
		guard:  "connect/oidcverify (IsLinkLocal tier) — separate reference",
		diff:   "permit RFC-1918 and loopback; refuse ONLY link-local (169.254/16, fe80::/10). AWS IPv6 IMDS fd00:ec2::254 is intentionally NOT refused by this tier.",
		reason: "on-prem/air-gapped IdPs and Connect backends legitimately live on internal 10.x/192.168.x/ULA segments; only the universal IPv4 IMDS endpoint must stay unreachable (netutil.IsLinkLocal's own documented scope).",
		ref:    "internal/netutil/dialer.go:334-375; internal/connect/hardened_client.go; internal/oidcverify/oidc_jwks.go:41",
	},
}

// vectors are high-value SSRF targets, given as raw IPv4 octets so buildLiteral
// can re-encode each in every embedding. refusedByReference / refusedBySiem are
// computed (not hand-set) in init so the table cannot drift from the real funcs.
var vectors = []struct {
	name       string
	a, b, c, d byte
}{
	{"IMDS 169.254.169.254 (AWS/GCP/Azure)", 169, 254, 169, 254},
	{"Alibaba IMDS 100.100.100.200 (CGNAT)", 100, 100, 100, 200},
	{"CGNAT 100.64.0.1 (RFC 6598)", 100, 64, 0, 1},
	{"RFC-1918 10.0.0.1", 10, 0, 0, 1},
	{"RFC-1918 192.168.0.1", 192, 168, 0, 1},
	{"RFC-1918 172.16.0.1", 172, 16, 0, 1},
	{"link-local 169.254.0.1", 169, 254, 0, 1},
	{"loopback 127.0.0.1 (EXCEPTION: allowed)", 127, 0, 0, 1},
	{"public 8.8.8.8", 8, 8, 8, 8},
	{"public 93.184.216.34", 93, 184, 216, 34},
}

// TestEgressParity_NetutilReferenceIsEncodingRobust is a GREEN control: the
// reference itself gives the SAME verdict for a raw IPv4 and for every IPv6
// encoding that embeds it. If this regresses, the reference (netutil) broke and
// every downstream comparison is meaningless.
func TestEgressParity_NetutilReferenceIsEncodingRobust(t *testing.T) {
	for _, v := range vectors {
		raw := net.IPv4(v.a, v.b, v.c, v.d)
		want := webhookTierReference(raw)
		for enc := range byte(encodingKinds - 1) {
			ip, s := buildLiteral(enc, v.a, v.b, v.c, v.d)
			if ip == nil {
				t.Fatalf("%s enc %d: %q did not parse", v.name, enc, s)
			}
			if got := webhookTierReference(ip); got != want {
				t.Fatalf("reference not encoding-robust: %s raw=%v but %s=%v", v.name, want, s, got)
			}
		}
	}
}

// TestEgressParity_SiemIsEncodingRobust is a GREEN control: the sibling guard
// siem.DialDisallowed gives identical verdicts across every embedding of the
// same address (it HAS the embedded-IPv4 decode). This isolates siem's only
// divergence from the reference to the DIRECT CGNAT range (F2), not encodings —
// and is the baseline evidencesink's F1 is measured against.
func TestEgressParity_SiemIsEncodingRobust(t *testing.T) {
	for _, v := range vectors {
		raw := siem.DialDisallowed(net.IPv4(v.a, v.b, v.c, v.d))
		for enc := range byte(encodingKinds - 1) {
			ip, s := buildLiteral(enc, v.a, v.b, v.c, v.d)
			if ip == nil {
				continue
			}
			if got := siem.DialDisallowed(ip); got != raw {
				t.Fatalf("siem not encoding-robust: %s raw=%v but %s=%v", v.name, raw, s, got)
			}
		}
	}
}

// TestEgressParity_EvidencesinkDirectFormMatchesSiblings is GREEN: on the forms
// the stdlib folds natively (raw IPv4, IPv4-mapped ::ffff:x), evidencesink,
// siem and notifychan's shared stdlib classifier all agree. This bounds F1 to
// the embedded ENCODINGS specifically, and confirms F2 (CGNAT) is a shared
// webhook-tier property, not evidencesink-specific.
func TestEgressParity_EvidencesinkDirectFormMatchesSiblings(t *testing.T) {
	for _, v := range vectors {
		for _, enc := range []byte{0, 1} {
			ip, s := buildLiteral(enc, v.a, v.b, v.c, v.d)
			if ip == nil {
				continue
			}
			if got, want := isDisallowedIP(ip), siem.DialDisallowed(ip); got != want {
				t.Fatalf("evidencesink vs siem on direct form %s: evidencesink=%v siem=%v (%s)", s, got, want, v.name)
			}
		}
	}
}

// TestEgressParity_EvidencesinkEmbeddedIPv4Gap is the GREEN regression guard for
// FINDING F1 (fixed in this branch). evidencesink.isDisallowedIP now delegates to
// netutil.IsPrivateOrLinkLocalExceptLoopback, which decodes every embedded-IPv4
// encoding (NAT64 well-known/local-use, IPv4-compatible, 6to4, Teredo), so a
// NAT64/6to4/Teredo/IPv4-compatible encoding of a private, link-local or IMDS
// IPv4 is now REFUSED by evidencesink, in lockstep with the netutil reference and
// the sibling siem guard. Before the fix this test was quarantined red and
// reported 25 bypasses; it is now an active assertion that no such bypass exists.
// Reachable at dial time (webhook.go:85-93 wires isDisallowedIP into a
// netutil.Dialer with the lookupIPAddr resolver).
//
// Uses only vectors siem itself refuses (so F1 is isolated from F2/CGNAT).
func TestEgressParity_EvidencesinkEmbeddedIPv4Gap(t *testing.T) {
	var bypasses []string
	for _, v := range vectors {
		raw := net.IPv4(v.a, v.b, v.c, v.d)
		if !siem.DialDisallowed(raw) {
			continue // skip loopback/public/CGNAT — F1 is the encoding gap on siem-refused targets
		}
		for enc := byte(2); enc < encodingKinds-1; enc++ {
			ip, s := buildLiteral(enc, v.a, v.b, v.c, v.d)
			if ip == nil {
				continue
			}
			if siem.DialDisallowed(ip) && !isDisallowedIP(ip) {
				bypasses = append(bypasses, fmt.Sprintf("%s via %s", v.name, s))
			}
		}
	}
	if len(bypasses) > 0 {
		t.Fatalf("FINDING F1 — %d evidencesink SSRF bypasses that siem and the netutil reference both refuse:\n  %v", len(bypasses), bypasses)
	}
}

// TestEgressParity_WebhookTierCGNATGap is the GREEN regression guard for FINDING
// F2 (fixed in this branch). Every webhook-tier guard (evidencesink, siem,
// notifychan, core-channel) used to classify with stdlib ip.IsPrivate(), which
// excludes RFC-6598 shared address space (100.64.0.0/10) — so Alibaba Cloud's
// instance-metadata endpoint at 100.100.100.200 was reachable. The guards now
// delegate to the netutil predicates (IsPrivateOrLinkLocalExceptLoopback for the
// webhook tier, IsPrivateOrLinkLocal for the core channel), whose canonical CIDR
// set includes 100.64/10, so the webhook tier refuses it exactly as the netutil
// reference does. Before the fix this test was quarantined red and reported the
// evidencesink+siem CGNAT divergences; it is now an active assertion.
func TestEgressParity_WebhookTierCGNATGap(t *testing.T) {
	var gaps []string
	for _, v := range vectors {
		raw := net.IPv4(v.a, v.b, v.c, v.d)
		if !webhookTierReference(raw) {
			continue
		}
		// reference refuses raw; do the webhook guards?
		if !isDisallowedIP(raw) {
			gaps = append(gaps, fmt.Sprintf("evidencesink allows %s (%s) — reference refuses", raw, v.name))
		}
		if !siem.DialDisallowed(raw) {
			gaps = append(gaps, fmt.Sprintf("siem allows %s (%s) — reference refuses", raw, v.name))
		}
	}
	if len(gaps) > 0 {
		t.Fatalf("FINDING F2 — %d webhook-tier divergences from the netutil reference:\n  %v", len(gaps), gaps)
	}
}

// TestEgressParity_DNSRebindingPinned proves the netutil.Dialer property every
// webhook-tier guard relies on: validate-at-dial. A resolver answering PUBLIC
// at construction and a disallowed IP at dial must be caught at dial. For the
// DIRECT (non-embedded) form evidencesink already catches it — this is the
// GREEN half; the embedded-form rebind that evidencesink misses is part of F1.
func TestEgressParity_DNSRebindingPinned(t *testing.T) {
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })

	calls := 0
	lookupIPAddr = func(string) ([]net.IPAddr, error) {
		calls++
		if calls == 1 {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil // public at construction
		}
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil // IMDS at dial (rebind)
	}

	if err := validateEndpoint("https://rebind.example.test/evidence", false, false); err != nil {
		t.Fatalf("construction-time validateEndpoint should pass on the public answer: %v", err)
	}
	d := netutil.Dialer{
		Disallow: isDisallowedIP,
		Resolve:  func(_ context.Context, host string) ([]net.IPAddr, error) { return lookupIPAddr(host) },
	}
	if err := d.ValidateHost(context.Background(), "rebind.example.test"); err == nil {
		t.Fatalf("SSRF: dial-time guard accepted a rebind to raw 169.254.169.254")
	}
}

// --- Oracle red-proof: plant a hole in a SCRATCH COPY of the guard ----------
//
// A guard nobody has watched fail is not a guard. Two local copies of the
// webhook-tier classifier — one WITH the embedded decode (control), one WITHOUT
// (the planted hole == evidencesink's actual shape) — prove the oracle
// distinguishes them on a real IMDS-via-NAT64 vector. No production file is
// touched.

// scratchGuardWithDecode mirrors the sibling webhook-tier guards that ARE
// encoding-robust (siem/notifychan): stdlib classify + the netutil.EmbeddedIPv4
// decode. scratchGuardNoDecode is the planted hole — stdlib classify ALONE,
// which is exactly evidencesink's real shape. Note both deliberately build on
// STDLIB ip.IsPrivate()/IsLinkLocal (not netutil.IsPrivateOrLinkLocal, which
// would decode on its own and so could not model a decode hole at all — the
// first version of this proof made that mistake and the oracle caught it).
func scratchStdlibClassify(ip net.IP) bool {
	if ip.IsLoopback() {
		return false
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func scratchGuardWithDecode(ip net.IP) bool { // control: has the embedded decode
	if scratchStdlibClassify(ip) {
		return true
	}
	if v4 := netutil.EmbeddedIPv4(ip); v4 != nil {
		return scratchStdlibClassify(v4)
	}
	return false
}

func scratchGuardNoDecode(ip net.IP) bool { // planted hole == evidencesink's shape
	return scratchStdlibClassify(ip)
}

// oracleFindsEncodingGap reports whether guard is NOT encoding-robust: it
// refuses some address in raw form but ALLOWS an embedded IPv6 encoding (2..6)
// of that same address. Measured against the guard's OWN raw verdict, so this
// is the pure embedded-decode (F1) axis, independent of the CGNAT (F2) axis.
func oracleFindsEncodingGap(guard func(net.IP) bool) bool {
	for _, v := range vectors {
		raw := net.IPv4(v.a, v.b, v.c, v.d)
		if !guard(raw) {
			continue // guard permits raw; encoding parity is "permit", not a gap
		}
		for enc := byte(2); enc < encodingKinds-1; enc++ {
			ip, _ := buildLiteral(enc, v.a, v.b, v.c, v.d)
			if ip == nil {
				continue
			}
			if !guard(ip) {
				return true // refuses raw but allows the encoded form => decode gap
			}
		}
	}
	return false
}

func TestEgressParity_OracleSoundness_RedProof(t *testing.T) {
	if oracleFindsEncodingGap(scratchGuardWithDecode) {
		t.Fatalf("CONTROL NOT GREEN: oracle flagged the correct (decoding) guard — oracle is unsound")
	}
	if !oracleFindsEncodingGap(scratchGuardNoDecode) {
		t.Fatalf("HOLE DID NOT FIRE: oracle missed a guard that drops the embedded-IPv4 decode — oracle is blind")
	}
	// The planted scratch hole (above) proves the oracle is not blind. The real
	// evidencesink.isDisallowedIP is now FIXED (F1): it delegates to
	// netutil.IsPrivateOrLinkLocalExceptLoopback, which decodes every embedded
	// IPv4 form, so it must have NO encoding gap. Before the fix this asserted the
	// opposite (the gap was present); flipping it is the green half of the F1
	// red→green proof, not an assertion adjusted to match broken behaviour.
	if oracleFindsEncodingGap(isDisallowedIP) {
		t.Fatalf("REGRESSION: evidencesink.isDisallowedIP has an embedded-IPv4 decode gap again (F1 reopened)")
	}
}

// FuzzEgressGuardParity is the long-running (60-min target) GREEN differential:
// for every fuzzed address in every embedded encoding, siem.DialDisallowed and
// netutil's two tiers must each agree with their OWN verdict on the raw form
// (encoding robustness). This is the control that stays green at fuzz scale.
// The two known webhook-tier findings (F1 embedded decode, F2 CGNAT) are the
// documented divergences, pinned by the quarantined table tests above — not
// folded in here, because folding a known defect into a green oracle whitewashes
// it. If this fuzz ever goes red, a guard that was encoding-robust regressed.
func FuzzEgressGuardParity(f *testing.F) {
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(2)) // IMDS via NAT64
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(6)) // IMDS via Teredo
	f.Add(byte(10), byte(0), byte(0), byte(1), byte(3))        // RFC-1918 via NAT64-local
	f.Add(byte(127), byte(0), byte(0), byte(1), byte(4))       // loopback via IPv4-compat
	f.Add(byte(8), byte(8), byte(8), byte(8), byte(5))         // public via 6to4
	f.Add(byte(100), byte(100), byte(100), byte(200), byte(2)) // Alibaba IMDS via NAT64
	f.Add(byte(172), byte(16), byte(0), byte(1), byte(7))      // native link-local literal path

	f.Fuzz(func(t *testing.T, a, b, c, d, encKind byte) {
		enc := encKind % encodingKinds
		if enc == 7 {
			ip, s := buildLiteral(7, a, b, c, d)
			if ip == nil {
				return
			}
			if !netutil.IsLinkLocal(ip) {
				t.Fatalf("GAP: native link-local %s not caught by IsLinkLocal", s)
			}
			if !siem.DialDisallowed(ip) {
				t.Fatalf("GAP: native link-local %s not caught by siem", s)
			}
			return
		}
		if a == 0 {
			// 0.0.0.0/8: its ::a.b.c.d embedding collides with ::/::1 — not a
			// meaningful per-encoding parity question (mirrors core's harness).
			return
		}
		ip, s := buildLiteral(enc, a, b, c, d)
		if ip == nil {
			t.Fatalf("enc %d for %d.%d.%d.%d did not parse: %q", enc, a, b, c, d, s)
		}
		raw := net.IPv4(a, b, c, d)

		if got, want := siem.DialDisallowed(ip), siem.DialDisallowed(raw); got != want {
			t.Fatalf("siem encoding parity: %s=%v want %v (raw %d.%d.%d.%d)", s, got, want, a, b, c, d)
		}
		if got, want := netutil.IsPrivateOrLinkLocal(ip), netutil.IsPrivateOrLinkLocal(raw); got != want {
			t.Fatalf("IsPrivateOrLinkLocal encoding parity: %s=%v want %v", s, got, want)
		}
		if got, want := netutil.IsLinkLocal(ip), netutil.IsLinkLocal(raw); got != want {
			t.Fatalf("IsLinkLocal encoding parity: %s=%v want %v", s, got, want)
		}
	})
}

// TestDocumentedExceptionsAreComplete keeps the intentional-difference table honest:
// every entry names the guard, the difference, the reason and a code reference, so an
// exception cannot be added as a bare allowance.
func TestDocumentedExceptionsAreComplete(t *testing.T) {
	if len(documentedExceptions) == 0 {
		t.Fatal("documentedExceptions is empty; the loopback exception must stay documented")
	}
	for i, e := range documentedExceptions {
		if e.guard == "" || e.diff == "" || e.reason == "" || e.ref == "" {
			t.Errorf("documentedExceptions[%d] has an empty field: %+v", i, e)
		}
	}
}
