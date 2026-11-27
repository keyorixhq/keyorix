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
