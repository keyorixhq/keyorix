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

	if ip := net.ParseIP(host); ip != nil {
		if d.disallow(ip) {
			return nil, fmt.Errorf("netutil: refusing to dial disallowed address %s", ip)
		}
		return dial(ctx, network, addr)
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

	// Validate every resolved address before dialing any of them — a hostname
	// that resolves to a mix of public and private addresses must not be
	// allowed through just because one answer happened to be checked first.
	var chosen net.IP
	for _, a := range addrs {
		if d.disallow(a.IP) {
			return nil, fmt.Errorf("netutil: host %q resolves to disallowed address %s; refusing to dial", host, a.IP)
		}
		if chosen == nil {
			chosen = a.IP
		}
	}

	// Dial the validated IP literal explicitly, not the hostname: this is the
	// step that actually closes the DNS-rebinding gap, since net.Dial on a
	// literal IP performs no further name resolution.
	pinnedAddr := net.JoinHostPort(chosen.String(), port)
	return dial(ctx, network, pinnedAddr)
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
// refuses. Covers RFC-1918, loopback, link-local (including cloud IMDS at
// 169.254.169.254), shared carrier-grade NAT (RFC 6598), and IPv6
// private/link-local equivalents.
var privateNetworkCIDRs = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{ // NOSONAR -- these are the SSRF-guard blocklist ranges themselves (RFC-1918/1122/6598 + IPv6 equivalents), not a live endpoint; hardcoding them is the point of IsPrivateOrLinkLocal
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // NOSONAR -- RFC-1918
		"127.0.0.0/8",    // loopback
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
	for _, cidr := range privateNetworkCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
