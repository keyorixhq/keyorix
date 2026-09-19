// Package netutil provides a shared SSRF-safe dialer used by every outbound
// client that connects to an operator/admin-controlled hostname (webhook and
// notification-channel endpoints, the dynamic-secrets admin DSN, cloud KMS
// endpoints, ...).
//
// The root-cause mistake this fixes (G48): several call sites across the
// codebase validated a target host against a private/link-local blocklist
// exactly once — at create/update/construction time — and then reused a
// long-lived client/config for the object's whole lifetime. The actual
// outbound connection later performs its OWN independent DNS resolution with
// no re-check, so a DNS-rebinding attacker (a name whose first answer is a
// public IP that passes validation, and whose second answer — returned to the
// real dial moments later — is a private/link-local address) trivially
// bypasses a validate-once guard.
//
// Dialer closes that gap by resolving and validating on EVERY dial, then
// connecting to the specific validated IP address it just checked — never the
// hostname again — so the connection itself cannot trigger a second,
// independent DNS answer that differs from the one just validated.
package netutil

import (
	"context"
	"fmt"
	"net"
)

// IPValidator reports whether ip must be refused as a dial target (e.g.
// private/link-local/loopback, per the caller's own policy — different
// packages in this codebase intentionally apply slightly different policies,
// e.g. whether loopback is permitted for local testing, so Dialer takes the
// policy as a parameter rather than hardcoding one).
type IPValidator func(ip net.IP) bool

// Resolver resolves host to its candidate IP addresses. A field on Dialer
// (not a package-level var) so each call site — and its tests — can supply an
// independent fake resolver without sharing global state.
type Resolver func(ctx context.Context, host string) ([]net.IPAddr, error)

// DefaultResolver resolves host via the standard library's resolver (real DNS).
func DefaultResolver(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// Dialer builds an SSRF-safe DialContext: a dial that resolves its target
// host, validates EVERY resolved address against Disallow, and — only if all
// of them pass — connects to the FIRST validated address explicitly, using
// that literal IP rather than the original hostname. Zero value is usable:
// Disallow defaults to permitting everything (a no-op guard — set it),
// Resolve defaults to DefaultResolver, and Dial defaults to a plain
// *net.Dialer.
//
// The DialContext method's signature (func(ctx, network, addr) (net.Conn,
// error)) matches http.Transport.DialContext and several DB drivers' own raw
// TCP dial hooks (pgconn.Config.DialFunc, mysql.Config.DialFunc), so the same
// Dialer value wires directly into any of them.
type Dialer struct {
	// Disallow reports whether ip must be refused. A nil Disallow permits
	// every address (no SSRF guard) — callers should always set this.
	Disallow IPValidator
	// Resolve resolves a hostname to candidate addresses. Defaults to
	// DefaultResolver (real DNS) when nil.
	Resolve Resolver
	// Dial performs the actual network dial once a safe address has been
	// chosen. Defaults to (&net.Dialer{}).DialContext when nil.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialContext resolves addr's host, validates every resolved IP against
// Disallow, and dials the first validated IP explicitly — never the hostname
// again — so a second, independent DNS resolution at actual-connect time
// (which a DNS-rebinding attacker controls) cannot hand back a different,
// unvalidated address than the one just checked. A literal IP in addr is
// validated directly, with no DNS lookup involved.
//
// Suitable as http.Transport.DialContext / http.Transport.DialTLSContext,
// pgconn.Config.DialFunc, mysql.Config.DialFunc, or any other dial hook
// sharing this exact signature.
func (d Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netutil: invalid dial address %q: %w", addr, err)
	}

	dial := d.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	chosen, err := d.resolveValidated(ctx, host)
	if err != nil {
		return nil, err
	}

	// Dial the validated IP literal explicitly, not the hostname: this is the
	// step that actually closes the DNS-rebinding gap, since net.Dial on a
	// literal IP performs no further name resolution.
	pinnedAddr := net.JoinHostPort(chosen.String(), port)
	return dial(ctx, network, pinnedAddr)
}

// ValidateHost resolves (or, for a literal IP, parses) host and confirms
// every candidate address passes Disallow — the same check DialContext
// performs before dialing — WITHOUT dialing anything. For a caller that must
// pre-validate a hostname discovered through a channel other than
// DialContext itself: e.g. a mongodb+srv:// URI's SRV-resolved target hosts,
// which the MongoDB Go driver resolves internally, before any caller-supplied
// dial hook is ever invoked (see internal/netutil/egress.go's
// Guard.ValidateSRVTargets, which uses this method).
func (d Dialer) ValidateHost(ctx context.Context, host string) error {
	_, err := d.resolveValidated(ctx, host)
	return err
}

// resolveValidated implements the shared resolve-then-validate logic behind
// both DialContext and ValidateHost: a literal IP is validated directly;
// otherwise host is resolved and EVERY candidate address is validated before
// any is returned — a hostname that resolves to a mix of public and private
// addresses must not be allowed through just because one answer happened to
// be checked first. Returns the first validated address.
func (d Dialer) resolveValidated(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if d.disallow(ip) {
			return nil, fmt.Errorf("netutil: refusing to dial disallowed address %s", ip)
		}
		return ip, nil
	}

	resolve := d.Resolve
	if resolve == nil {
		resolve = DefaultResolver
	}
	addrs, err := resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("netutil: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("netutil: host %q did not resolve to any address", host)
	}

	var chosen net.IP
	for _, a := range addrs {
		if d.disallow(a.IP) {
			return nil, fmt.Errorf("netutil: host %q resolves to disallowed address %s; refusing to dial", host, a.IP)
		}
		if chosen == nil {
			chosen = a.IP
		}
	}
	return chosen, nil
}

// DialContextTCP adapts DialContext to the func(ctx, addr) (net.Conn, error)
// shape some dial hooks use when the network is implicitly "tcp" (e.g.
// mysql.Config.DialFunc's older form / callers that don't need the network
// parameter).
func (d Dialer) DialContextTCP(ctx context.Context, addr string) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d Dialer) disallow(ip net.IP) bool {
	return d.Disallow != nil && d.Disallow(ip)
}

// privateNetworkCIDRs is the canonical set of IP ranges IsPrivateOrLinkLocal
// refuses. Covers RFC-1918, loopback, "this network" (RFC 1122 §3.2.1.3),
// link-local (including cloud IMDS at 169.254.169.254), shared carrier-grade
// NAT (RFC 6598), and IPv6 private/link-local equivalents.
var privateNetworkCIDRs = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{ // NOSONAR -- these are the SSRF-guard blocklist ranges themselves (RFC-1918/1122/6598 + IPv6 equivalents), not a live endpoint; hardcoding them is the point of IsPrivateOrLinkLocal
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // NOSONAR -- RFC-1918
		"127.0.0.0/8",    // loopback
		"0.0.0.0/8",      // NOSONAR -- RFC 1122 "this network"; many kernels (Linux included) treat a connect() to 0.0.0.0 as a connect to loopback, making it a live SSRF bypass, not merely a non-routable curiosity
		"169.254.0.0/16", // NOSONAR -- link-local / cloud IMDS
		"100.64.0.0/10",  // NOSONAR -- shared address space (RFC 6598)
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	} {
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// IsPrivateOrLinkLocal reports whether ip falls in a private, loopback,
// link-local, IMDS, or carrier-grade-NAT range — the canonical "disallowed as
// an SSRF target" check shared by every backend-infrastructure dial site
// (dynamic-secrets admin DSN, cloud KMS endpoints) where even loopback is
// refused, since those targets are the Keyorix deployment's own backing
// services, not a webhook receiver an operator might legitimately run
// locally during testing.
func IsPrivateOrLinkLocal(ip net.IP) bool {
	return matchesCIDRsWithEmbedded(ip, privateNetworkCIDRs)
}

// matchesCIDRsWithEmbedded reports whether ip itself falls in one of cidrs, OR —
// for an IPv6 address — whether the IPv4 address it EMBEDS does. net.IPNet.Contains
// folds IPv4-MAPPED (::ffff:x) via To4, so a direct cidrs check already covers that
// form — but NAT64 (RFC 6052 well-known 64:ff9b::/96; e.g. 64:ff9b::a9fe:a9fe ->
// cloud IMDS 169.254.169.254) and deprecated IPv4-compatible (::x) are NOT folded,
// so a target written in either encoding would otherwise slip past a direct-only
// check. Decode the embedded IPv4 and check THAT against cidrs too — decode, not a
// wholesale-prefix block, so a NAT64/compat address embedding a PUBLIC IPv4 (the
// legitimate egress path in an IPv6-only deployment) is still permitted. Shared by
// IsPrivateOrLinkLocal and IsLinkLocal so both predicates get the same embedded-IPv4
// decode coverage, each against its own cidrs list (#1937 fixed this for
// IsPrivateOrLinkLocal only; IsLinkLocal needed the identical fix for the same
// reason — no legitimate Connect backend, egress target, or any other caller of
// this narrower predicate lives at a NAT64/compat-encoded link-local address either).
func matchesCIDRsWithEmbedded(ip net.IP, cidrs []*net.IPNet) bool {
	if inCIDRs(ip, cidrs) {
		return true
	}
	if v4 := embeddedIPv4(ip); v4 != nil && inCIDRs(v4, cidrs) {
		return true
	}
	return false
}

func inCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// nat64WellKnownPrefix is the RFC 6052 well-known NAT64 prefix; an address inside
// it carries its IPv4 target in the low 32 bits.
var _, nat64WellKnownPrefix, _ = net.ParseCIDR("64:ff9b::/96")

// embeddedIPv4 returns the IPv4 address carried by an IPv6 address that embeds one
// in its low 32 bits — NAT64 well-known (64:ff9b::/96) or deprecated IPv4-compatible
// (::/96, i.e. ::a.b.c.d) — or nil if ip carries no such embedded IPv4. IPv4-MAPPED
// (::ffff:x) is intentionally not handled here: net.IPNet.Contains already folds it
// via To4, so the caller's direct CIDR check covers it. The unspecified (::) and
// loopback (::1) addresses fall in ::/96 but decode to 0.0.0.0 / 0.0.0.1, which the
// caller's direct check (::1/128) and the IPv4 CIDRs handle correctly regardless.
func embeddedIPv4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil // not IPv6, or already an IPv4 form To4 handles
	}
	isCompat := true // ::/96 : first 12 bytes zero
	for _, b := range ip16[:12] {
		if b != 0 {
			isCompat = false
			break
		}
	}
	if isCompat || nat64WellKnownPrefix.Contains(ip16) {
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	}
	return nil
}

// linkLocalCIDRs is the narrow subset of privateNetworkCIDRs that IsLinkLocal
// refuses: IPv4/IPv6 link-local only. This is deliberately much smaller than the
// full private-range set — it exists for egress to operator-configured OIDC
// issuers (JWKS fetch, discovery), where an RFC-1918/on-prem target is a
// FIRST-CLASS legitimate deployment (keyorix is on-prem/air-gapped first, so the
// IdP frequently lives on an internal 10.x/192.168.x segment) and http-on-loopback
// is a supported dev shape — but the cloud instance-metadata endpoint
// (169.254.169.254, shared by AWS/GCP/Azure) must never be reachable via a
// misconfigured or compromised issuer/jwks_uri. IsPrivateOrLinkLocal is therefore
// too broad for this seam; IsLinkLocal is the right-sized guard.
//
// The one metadata surface intentionally NOT covered here is AWS's IPv6 IMDS
// (fd00:ec2::254, inside fc00::/7 unique-local): blocking all of fc00::/7 would
// break legitimate on-prem IPv6 ULA issuers, and the IPv4 169.254.169.254 endpoint
// is reachable on every cloud that offers IMDS, so the residual is negligible for
// keyorix's deployment profile. Documented here rather than silently omitted.
var linkLocalCIDRs = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{ // NOSONAR -- SSRF-guard blocklist ranges themselves (IPv4/IPv6 link-local), not a live endpoint
		"169.254.0.0/16", // NOSONAR -- IPv4 link-local / cloud IMDS (AWS/GCP/Azure 169.254.169.254)
		"fe80::/10",      // IPv6 link-local
	} {
		if _, n, _ := net.ParseCIDR(cidr); n != nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// IsLinkLocal reports whether ip is in an IPv4 or IPv6 link-local range, INCLUDING
// a NAT64 (64:ff9b::/96) or deprecated IPv4-compatible (::x) IPv6 encoding of a
// link-local IPv4 address (e.g. 64:ff9b::a9fe:a9fe embeds cloud IMDS
// 169.254.169.254 — see matchesCIDRsWithEmbedded's doc comment) — the narrow
// SSRF-target check for egress to operator-configured OIDC issuers (JWKS fetch and
// discovery) and to Connect backend addresses (internal/connect's hardened
// transport), where RFC-1918/on-prem targets are legitimate but the cloud
// instance-metadata endpoint must never be reached via a misconfigured or
// compromised target. See linkLocalCIDRs for why this is deliberately narrower
// than IsPrivateOrLinkLocal.
func IsLinkLocal(ip net.IP) bool {
	return matchesCIDRsWithEmbedded(ip, linkLocalCIDRs)
}
