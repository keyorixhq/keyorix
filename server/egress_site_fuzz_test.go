// egress_site_fuzz_test.go — V7-GAP-1: site-wiring parity for the SSO OIDC-discovery
// transport (oidcDiscoveryTransport). Same reasoning and policy as
// internal/oidcverify/egress_site_fuzz_test.go: the guard is a DialContext replacement
// on a clone of http.DefaultTransport, link-local only, and only a test that dials
// through the real transport notices if that line goes missing.
package main

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

func FuzzOIDCDiscoveryTransportEgressParity(f *testing.F) {
	egressref.Run(f, "server.oidcDiscoveryTransport",
		func() egressref.DialFunc { return oidcDiscoveryTransport.DialContext },
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
