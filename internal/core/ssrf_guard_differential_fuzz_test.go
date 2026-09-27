// FuzzSSRFGuardDifferential is a single differential harness driving one fuzzed
// address through every independent SSRF guard in the codebase that decides
// whether a target is "internal" and must be refused:
//
//  1. netutil.IsPrivateOrLinkLocal — the backend-infrastructure policy (admin
//     DSN, cloud KMS endpoints; even loopback refused).
//  2. netutil.IsLinkLocal — the narrower policy for operator-configured
//     egress (OIDC/JWKS, Connect backends), where RFC-1918/on-prem targets are
//     legitimate but cloud IMDS must never be reachable.
//  3. internal/audit/siem's isDisallowedIP (exported here for fuzzing as
//     IsDisallowedIPForFuzz) — the SIEM-forwarder dial-time policy (loopback
//     PERMITTED).
//  4. internal/core's own isChannelDisallowedIP — the notification-channel
//     webhook dial-time policy (loopback REFUSED, unlike #3).
//  5. internal/connect/hardened_client.go's connectGuardedDialer and
//     internal/core/oidc_jwks.go's jwksEgressTransport: both are UNEXPORTED,
//     but both are, verified directly against the current tree
//     (hardened_client.go:77-82, oidc_jwks.go:41), nothing more than
//     `netutil.Dialer{Disallow: netutil.IsLinkLocal}` with no additional
//     logic of their own — so driving netutil.Dialer{Disallow:
//     netutil.IsLinkLocal}.ValidateHost with a literal-IP host (which never
//     touches a resolver — see resolveValidated's literal-IP short-circuit)
//     exercises the EXACT mechanism both wire in, not a re-derivation of it.
//     A future change that makes either site diverge from this exact
//     construction (e.g. swaps in a different Disallow policy, or adds
//     extra normalization before the Dialer sees the host) would silently
//     stop being covered by this citation — grep hardened_client.go and
//     oidc_jwks.go for `netutil.Dialer{` if this file's assertions ever look
//     suspiciously irrelevant.
//  6. internal/core's validateAdminDSNHost (dynamic_secrets.go) — the
//     admin-DSN SSRF guard, exercised through literal-IP-only DSNs (both
//     PostgreSQL multi-host forms: URL h1:port,h2:port and key-value
//     host=h1,h2) so no real DNS lookup ever fires (see below).
//
// Oracle (sound, encoding-parity — mirrors FuzzIPv4EmbeddingSSRFParity's own
// established shape, generalized to every guard above and to the 6to4/Teredo/
// NAT64-local-use encodings that fuzzer does not cover): for each of the four
// distinct POLICIES above (#1-#4; #5 reduces to #2's policy, #6 to #1's), the
// "ground truth" verdict is the policy's OWN real verdict on the RAW,
// unencoded IPv4 form (net.IPv4(a,b,c,d)) — computed by calling the real
// production function, never hand-derived, so this harness cannot itself
// encode a wrong assumption about a stdlib edge case (same reasoning
// FuzzIPv4EmbeddingSSRFParity already applies). Every IPv6 encoding that
// embeds the SAME underlying IPv4 address (IPv4-mapped, NAT64 well-known,
// NAT64 local-use, deprecated IPv4-compatible, 6to4, Teredo) must produce the
// IDENTICAL verdict from the SAME policy — a divergence is exactly an SSRF
// bypass (private target reachable via the encoding a guard forgot) or an
// over-block (public target refused via one encoding only, breaking
// legitimate IPv6-only egress). A native (non-embedding) IPv6 link-local
// literal (fe80::.../10) is checked separately: it must be refused by every
// link-local-sensitive policy regardless of its low bits, AND a zone-ID
// suffix on it (fe80::1%eth0) must still be caught by validateAdminDSNHost's
// explicit zone-strip path (dynamic_secrets.go:240-254) — a regression guard
// for the exact bypass that path's own doc comment describes.
//
// Deliberately OUT of scope, to keep this harness fast (60s local run budget)
// and free of real network calls: decimal/octal/hex-form and trailing-dot
// IPv4 textual representations (e.g. "2130706433", "0x7f000001",
// "127.0.0.1."). net.ParseIP is strict RFC-4291/RFC-791 dotted-decimal only
// and returns nil for every one of these across the whole codebase (every
// guard here is confirmed, by direct source read, to gate its literal-IP
// fast path on net.ParseIP and nothing more permissive) — so they uniformly
// fall through to hostname resolution everywhere, never diverging BETWEEN
// guards on whether they're "literal" (the only property a fuzzer running
// with no network can safely assert here). Actually exercising that
// fallthrough would require a live or faked DNS resolver per guard;
// validateAdminDSNHost's own fallthrough (net.LookupHost, dynamic_secrets.go:
// 255) is a REAL DNS call with no injectable seam, so feeding it a
// non-literal host from a fuzz iteration would make this harness's runtime
// depend on live network resolution — unacceptable for a fast, offline fuzz
// target. This is a documented scope decision, not a silent gap: the
// security-relevant vector this harness closes is a same-host literal-IP
// encoding a guard fails to decode, not a DNS-dependent hostname bypass.
//
// Red-proof (see the PR body for full output): commenting out the
// nat64LocalUsePrefix96/sixToFourPrefix/teredoPrefix branches in
// internal/netutil/dialer.go's embeddedIPv4 one at a time reliably fails this
// fuzzer on its own seed corpus (an IMDS/loopback target encoded in the
// disabled form stops being recognised by every policy built on
// matchesCIDRsWithEmbedded); commenting out either forwarder.go's or
// notification_channels.go's own `if v4 := netutil.EmbeddedIPv4(ip); ...`
// branch does the same for policies #3/#4 specifically.
package core

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/audit/siem"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// ssrfEncKindCount is the number of distinct address shapes buildSSRFLiteral
// knows how to build: encodings 0-6 all embed the SAME fuzzed IPv4 octets
// (raw, then 6 IPv6 embeddings); encoding 7 is a native, non-embedding IPv6
// link-local literal, checked by a separate assertion branch.
const ssrfEncKindCount = 8

// buildSSRFLiteral returns the net.IP and canonical textual form for encKind
// applied to octets a.b.c.d. Built via fmt.Sprintf + net.ParseIP (not raw byte
// manipulation) so it needs no access to netutil's unexported prefix vars —
// deliberately independent of dialer.go's own construction, so a bug in THIS
// harness's understanding of an encoding's byte layout cannot cancel out a
// matching bug in dialer.go's embeddedIPv4 (a shared derivation would risk
// exactly that).
func buildSSRFLiteral(encKind, a, b, c, d byte) (net.IP, string) {
	var s string
	switch encKind % ssrfEncKindCount {
	case 0: // raw IPv4
		s = fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
	case 1: // IPv4-mapped
		s = fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d)
	case 2: // NAT64 well-known (64:ff9b::/96)
		s = fmt.Sprintf("64:ff9b::%d.%d.%d.%d", a, b, c, d)
	case 3: // NAT64 local-use, /96 shape (64:ff9b:1::/96)
		s = fmt.Sprintf("64:ff9b:1::%d.%d.%d.%d", a, b, c, d)
	case 4: // deprecated IPv4-compatible (::a.b.c.d)
		s = fmt.Sprintf("::%d.%d.%d.%d", a, b, c, d)
	case 5: // 6to4 (2002:WWXX:YYZZ::/48) -- embeds a.b.c.d directly, no XOR
		s = fmt.Sprintf("2002:%02x%02x:%02x%02x::", a, b, c, d)
	case 6: // Teredo (2001::/32) -- embeds a.b.c.d XORed with 0xff
		s = fmt.Sprintf("2001::%02x%02x:%02x%02x", a^0xff, b^0xff, c^0xff, d^0xff)
	default: // 7: native IPv6 link-local literal -- NOT an embedding of a.b.c.d
		s = fmt.Sprintf("fe80::%02x%02x:%02x%02x", a, b, c, d)
	}
	return net.ParseIP(s), s
}

// bracketIfIPv6 wraps an IPv6 literal in [] for use as a URL-form DSN host —
// required by RFC 3986 (and enforced by pgx.ParseConfig: confirmed directly,
// an unbracketed postgres://user@64:ff9b::8.8.8.8:5432/db is REJECTED by pgx
// itself with a parse error, never reaching dialPostgres at all) so that
// omitting it here would test a DSN shape no real admin_dsn config could ever
// use in the first place — not a reachable SSRF bypass, just an invalid
// fixture. An IPv4 literal (no colon) is returned unchanged.
func bracketIfIPv6(s string) string {
	if strings.Contains(s, ":") {
		return "[" + s + "]"
	}
	return s
}

// jwksAndConnectGuardedDialer reconstructs, byte-for-byte, the netutil.Dialer
// value both internal/connect/hardened_client.go's connectGuardedDialer and
// internal/core/oidc_jwks.go's jwksEgressTransport wire in -- see this file's
// doc comment (#5) for why this is the real mechanism, not a stand-in.
func jwksAndConnectGuardedDialer() netutil.Dialer {
	return netutil.Dialer{Disallow: netutil.IsLinkLocal}
}

func FuzzSSRFGuardDifferential(f *testing.F) {
	// Known regression shapes: cloud IMDS and loopback via every embedding,
	// plus a multi-host admin DSN where only the SECOND host is the private
	// one (the exact gap validateAdminDSNHost's own #FuzzAdminDSNHostSSRFGuard
	// sibling test disclaims as "documented follow-up").
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(0), byte(8), byte(8), byte(8), byte(8), false) // IMDS, raw
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(2), byte(8), byte(8), byte(8), byte(8), false) // IMDS via NAT64 well-known
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(3), byte(8), byte(8), byte(8), byte(8), false) // IMDS via NAT64 local-use
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(4), byte(8), byte(8), byte(8), byte(8), false) // IMDS via IPv4-compatible
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(5), byte(8), byte(8), byte(8), byte(8), false) // IMDS via 6to4
	f.Add(byte(169), byte(254), byte(169), byte(254), byte(6), byte(8), byte(8), byte(8), byte(8), false) // IMDS via Teredo
	f.Add(byte(127), byte(0), byte(0), byte(1), byte(4), byte(8), byte(8), byte(8), byte(8), false)       // loopback via IPv4-compatible
	f.Add(byte(10), byte(0), byte(0), byte(1), byte(7), byte(8), byte(8), byte(8), byte(8), false)        // native fe80 link-local literal
	f.Add(byte(8), byte(8), byte(8), byte(8), byte(0), byte(169), byte(254), byte(169), byte(254), true)  // multi-host DSN: 2nd host is IMDS
	f.Add(byte(93), byte(184), byte(216), byte(34), byte(0), byte(1), byte(1), byte(1), byte(1), false)   // public control, both hosts

	f.Fuzz(func(t *testing.T, a, b, c, d, encKind, a2, b2, c2, d2 byte, multiHost bool) {
		if a == 0 && encKind%ssrfEncKindCount != 7 {
			// Mirrors FuzzIPv4EmbeddingSSRFParity's own documented exclusion:
			// 0.0.0.0/8 ("this network") is reserved, and its IPv4-compatible
			// embedding ::a.b.c.d collides bit-for-bit with :: (unspecified,
			// a==b==c==d==0) and ::1 (loopback, a==b==c==0,d==1) -- genuinely
			// different, meaningful IPv6 addresses in their own right, not
			// alternate spellings of 0.0.0.1/0.0.0.2/etc. Per-host encoding
			// parity isn't a meaningful question here, so this harness
			// excludes it exactly as its sibling does, rather than asserting
			// a "parity" that isn't one.
			return
		}
		enc, encStr := buildSSRFLiteral(encKind, a, b, c, d)
		if enc == nil {
			t.Fatalf("failed to build encoding %d for %d.%d.%d.%d: %q did not parse", encKind%ssrfEncKindCount, a, b, c, d, encStr)
		}

		ctx := context.Background()
		dialer := jwksAndConnectGuardedDialer()

		if encKind%ssrfEncKindCount == 7 {
			// Native link-local literal: unconditionally refused by every
			// link-local-sensitive policy, regardless of its low bits.
			if !netutil.IsLinkLocal(enc) {
				t.Fatalf("GAP: native link-local literal %s not recognised by IsLinkLocal", encStr)
			}
			if !netutil.IsPrivateOrLinkLocal(enc) {
				t.Fatalf("GAP: native link-local literal %s not recognised by IsPrivateOrLinkLocal", encStr)
			}
			if !siem.IsDisallowedIPForFuzz(enc) {
				t.Fatalf("GAP: native link-local literal %s not recognised by siem.isDisallowedIP", encStr)
			}
			if !isChannelDisallowedIP(enc) {
				t.Fatalf("GAP: native link-local literal %s not recognised by isChannelDisallowedIP", encStr)
			}
			if err := dialer.ValidateHost(ctx, encStr); err == nil {
				t.Fatalf("SSRF BYPASS: netutil.Dialer{Disallow: IsLinkLocal} (connect/jwks wiring) accepted native link-local literal %s", encStr)
			}
			if err := validateAdminDSNHost("host=" + encStr + " port=5432 user=u dbname=d"); err == nil {
				t.Fatalf("SSRF BYPASS: validateAdminDSNHost accepted native link-local literal %s", encStr)
			}
			// Zone-ID regression guard (dynamic_secrets.go:240-254): a
			// zone-qualified form of this exact address must still be
			// caught, not silently fall through to net.LookupHost (which
			// errors on a zone-qualified name and, per that function's own
			// "unresolvable at register time" contract, would otherwise
			// skip validation entirely).
			zoned := encStr + "%eth0"
			if err := validateAdminDSNHost("host=" + zoned + " port=5432 user=u dbname=d"); err == nil {
				t.Fatalf("SSRF BYPASS: validateAdminDSNHost accepted zone-qualified link-local literal %q (zone-strip regression)", zoned)
			}
			return
		}

		// Encodings 0-6 all embed the SAME underlying a.b.c.d -- ground truth
		// for each policy is that policy's OWN verdict on the raw form,
		// computed via the real function (never hand-derived).
		rawV4 := net.IPv4(a, b, c, d)

		wantPLL := netutil.IsPrivateOrLinkLocal(rawV4)
		if got := netutil.IsPrivateOrLinkLocal(enc); got != wantPLL {
			t.Fatalf("ENCODING PARITY (IsPrivateOrLinkLocal): raw %d.%d.%d.%d=%v but %s(%s)=%v", a, b, c, d, wantPLL, encStr, enc, got)
		}

		wantLL := netutil.IsLinkLocal(rawV4)
		if got := netutil.IsLinkLocal(enc); got != wantLL {
			t.Fatalf("ENCODING PARITY (IsLinkLocal): raw %d.%d.%d.%d=%v but %s(%s)=%v", a, b, c, d, wantLL, encStr, enc, got)
		}

		wantSiem := siem.IsDisallowedIPForFuzz(rawV4)
		if got := siem.IsDisallowedIPForFuzz(enc); got != wantSiem {
			t.Fatalf("ENCODING PARITY (siem.isDisallowedIP): raw %d.%d.%d.%d=%v but %s(%s)=%v", a, b, c, d, wantSiem, encStr, enc, got)
		}

		wantChannel := isChannelDisallowedIP(rawV4)
		if got := isChannelDisallowedIP(enc); got != wantChannel {
			t.Fatalf("ENCODING PARITY (isChannelDisallowedIP): raw %d.%d.%d.%d=%v but %s(%s)=%v", a, b, c, d, wantChannel, encStr, enc, got)
		}

		// #5: connect/jwks wiring, via the literal-IP fast path (no DNS).
		rawAllowed := dialer.ValidateHost(ctx, rawV4.String()) == nil
		if encAllowed := dialer.ValidateHost(ctx, encStr) == nil; encAllowed != rawAllowed {
			t.Fatalf("ENCODING PARITY (connect/jwks Dialer{Disallow: IsLinkLocal}): raw %d.%d.%d.%d allowed=%v but %s(%s) allowed=%v", a, b, c, d, rawAllowed, encStr, enc, encAllowed)
		}

		// #6: admin-DSN guard, literal-IP-only (net.LookupHost never fires
		// for a literal IP -- see validateAdminDSNSingleHost's own
		// net.ParseIP branch) -- single host in both DSN forms, plus a
		// multi-host DSN (both PostgreSQL forms) putting the SAME encoded
		// literal as either the first or the second failover host, paired
		// with an independent second address (a2,b2,c2,d2) as the other
		// host so a private target hiding behind a public first host is
		// still caught.
		wantAdmin := isPrivateIP(rawV4) // validateAdminDSNHost's own private/link-local definition
		singleURL := "postgres://user:pass@" + bracketIfIPv6(encStr) + ":5432/db"
		singleKV := "host=" + encStr + " port=5432 user=u dbname=d"
		if (validateAdminDSNHost(singleURL) == nil) != !wantAdmin {
			t.Fatalf("ENCODING PARITY (validateAdminDSNHost, URL single-host): raw %d.%d.%d.%d wantPrivate=%v but dsn=%q err=%v", a, b, c, d, wantAdmin, singleURL, validateAdminDSNHost(singleURL))
		}
		if (validateAdminDSNHost(singleKV) == nil) != !wantAdmin {
			t.Fatalf("ENCODING PARITY (validateAdminDSNHost, key-value single-host): raw %d.%d.%d.%d wantPrivate=%v but dsn=%q err=%v", a, b, c, d, wantAdmin, singleKV, validateAdminDSNHost(singleKV))
		}

		other := fmt.Sprintf("%d.%d.%d.%d", a2, b2, c2, d2)
		otherIP := net.ParseIP(other)
		wantOtherPrivate := otherIP != nil && isPrivateIP(otherIP)
		wantMultiPrivate := wantAdmin || wantOtherPrivate

		bracketedEnc, bracketedOther := bracketIfIPv6(encStr), bracketIfIPv6(other)
		var multiURL, multiKV string
		if multiHost {
			// encoded literal first, other second
			multiURL = "postgres://user@" + bracketedEnc + ":5432," + bracketedOther + ":5432/db"
			multiKV = "host=" + encStr + "," + other + " port=5432,5432 user=u dbname=d"
		} else {
			// other first, encoded literal second -- the "not just the
			// first host" case
			multiURL = "postgres://user@" + bracketedOther + ":5432," + bracketedEnc + ":5432/db"
			multiKV = "host=" + other + "," + encStr + " port=5432,5432 user=u dbname=d"
		}
		if (validateAdminDSNHost(multiURL) == nil) != !wantMultiPrivate {
			t.Fatalf("MULTI-HOST SSRF BYPASS (validateAdminDSNHost, URL multi-host): wantPrivate=%v (self=%v other=%v) but dsn=%q err=%v", wantMultiPrivate, wantAdmin, wantOtherPrivate, multiURL, validateAdminDSNHost(multiURL))
		}
		if (validateAdminDSNHost(multiKV) == nil) != !wantMultiPrivate {
			t.Fatalf("MULTI-HOST SSRF BYPASS (validateAdminDSNHost, key-value multi-host): wantPrivate=%v (self=%v other=%v) but dsn=%q err=%v", wantMultiPrivate, wantAdmin, wantOtherPrivate, multiKV, validateAdminDSNHost(multiKV))
		}
	})
}
