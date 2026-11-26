// egress_site_fuzz_test.go — V7-GAP-1: site-wiring parity for the JWKS fetch transport.
//
// FuzzSSRFGuardDifferential (internal/core) and FuzzEgressDialEnforcement
// (internal/netutil) prove the predicate and the Dialer. Neither proves that THIS
// site's transport actually carries the guard: jwksEgressTransport is a package var
// whose DialContext is replaced after cloning http.DefaultTransport, so a refactor that
// drops that line leaves every netutil test green. This target drives the real
// transport's DialContext.
//
// Policy under test (documented intentional difference, egressref's package comment):
// link-local only, in every encoding; RFC-1918, loopback, CGNAT and ULA stay reachable
// because an on-prem IdP is a first-class deployment.
package oidcverify

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

func FuzzJWKSTransportEgressParity(f *testing.F) {
	egressref.Run(f, "oidcverify.jwksEgressTransport",
		func() egressref.DialFunc { return jwksEgressTransport.DialContext },
		egressref.LinkLocalTier)
}
