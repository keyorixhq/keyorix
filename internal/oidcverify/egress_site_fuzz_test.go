// egress_site_fuzz_test.go — V7-GAP-1: site-wiring parity for the JWKS fetch transport.
//
// FuzzSSRFGuardDifferential (internal/core) and FuzzEgressDialEnforcement
// (internal/netutil) prove the predicate and the Dialer. Neither proves that THIS
// site's transport actually carries the guard: jwksEgressTransport is a package var
// whose DialContext is replaced after cloning http.DefaultTransport, so a refactor that
// drops that line leaves every netutil test green. This target takes the transport from
// the client NewHTTPJWKSResolver builds, so it also notices if that client stops using
// jwksEgressTransport.
//
// Policy under test (documented intentional difference, egressref's package comment):
// link-local only, in every encoding; RFC-1918, loopback, CGNAT and ULA stay reachable
// because an on-prem IdP is a first-class deployment.
package oidcverify

import (
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

func FuzzJWKSTransportEgressParity(f *testing.F) {
	r, err := NewHTTPJWKSResolver(map[string]string{"i": "https://idp.example.test/jwks"})
	if err != nil {
		f.Fatal(err)
	}
	tr, ok := r.client.Transport.(*http.Transport)
	if !ok {
		f.Fatalf("the JWKS client's transport is %T, not the guarded *http.Transport", r.client.Transport)
	}
	egressref.Run(f, "oidcverify.jwksEgressTransport",
		func() egressref.DialFunc { return tr.DialContext },
		egressref.LinkLocalTier)
}

// FuzzJWKSResolverRebinding drives a hostname through the stdlib resolver (an in-process
// DNS stub, see egressref.RebindDNS) whose answer changes after the first lookup, and
// dials it through the client NewHTTPJWKSResolver builds. It does NOT verify a real DNS
// server, the cgo resolver, or the egress-proxy case (the dial then targets the proxy).
func FuzzJWKSResolverRebinding(f *testing.F) {
	r, err := NewHTTPJWKSResolver(map[string]string{"i": "https://idp.example.test/jwks"})
	if err != nil {
		f.Fatal(err)
	}
	tr, ok := r.client.Transport.(*http.Transport)
	if !ok {
		f.Fatalf("the JWKS client's transport is %T, not the guarded *http.Transport", r.client.Transport)
	}
	egressref.RunRebind(f, func() egressref.DialFunc { return tr.DialContext }, egressref.LinkLocalTier)
}
