// egress_site_fuzz_test.go — V7-GAP-1: site-wiring parity for the SSO OIDC-discovery
// transport (oidcDiscoveryTransport). Same reasoning and policy as
// internal/oidcverify/egress_site_fuzz_test.go: the guard is a DialContext replacement
// on a clone of http.DefaultTransport, link-local only, and only a test that dials
// through the real transport notices if that line goes missing.
package main

import (
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

func FuzzOIDCDiscoveryTransportEgressParity(f *testing.F) {
	egressref.Run(f, "server.oidcDiscoveryTransport",
		func() egressref.DialFunc { return oidcDiscoveryTransport.DialContext },
		egressref.LinkLocalTier)
}

// FuzzSSOExchangeTransportEgressParity (#4738) drives the dial hook of the client
// the OIDC code exchange really runs on: the provider's HTTPClient as
// buildSSOProviders builds it from a discovery document, not the transport
// variable. A provider built with another client, or with a transport that lost
// the guard, turns this red. Not covered: the redirect policy (see
// TestSSOExchangeClientIsTheDiscoveryClient) and DNS rebinding against the exchange
// client itself (FuzzOIDCDiscoveryResolverRebinding drives the transport variable;
// see docs/security/egress-inventory.md).
func FuzzSSOExchangeTransportEgressParity(f *testing.F) {
	p := buildSSOExchangeTestProvider(f)
	tr, ok := p.HTTPClient.Transport.(*http.Transport)
	if !ok || tr.DialContext == nil {
		f.Fatalf("exchange client transport is %T, want an *http.Transport with a dial hook", p.HTTPClient.Transport)
	}
	egressref.Run(f, "server.ssoIdPHTTPClient(exchange)",
		func() egressref.DialFunc { return tr.DialContext },
		egressref.LinkLocalTier)
}

// FuzzOIDCDiscoveryResolverRebinding drives a hostname through the stdlib resolver (an
// in-process DNS stub, see egressref.RebindDNS) whose answer changes after the first
// lookup, and dials it through oidcDiscoveryTransport. It does NOT verify a real DNS
// server, the cgo resolver, or the egress-proxy case, and it drives the transport
// variable, not the inline client of the discovery call.
func FuzzOIDCDiscoveryResolverRebinding(f *testing.F) {
	egressref.RunRebind(f, func() egressref.DialFunc { return oidcDiscoveryTransport.DialContext },
		egressref.LinkLocalTier)
}
