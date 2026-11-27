//go:build !noaws

package connect

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

// FuzzConnectAWSTransportEgressParity dials through awsSMHTTPClient, the client
// awssm.go's client() installs in the SDK (egress_site_fuzz_test.go).
func FuzzConnectAWSTransportEgressParity(f *testing.F) {
	egressref.Run(f, "connect.aws", func() egressref.DialFunc {
		return siteDial(awsSMHTTPClient())
	}, egressref.LinkLocalTier)
}

// FuzzConnectAWSResolverRebinding drives a hostname through the stdlib resolver (an
// in-process DNS stub, see egressref.RebindDNS) whose answer changes after the first
// lookup, and dials it through awsSMHTTPClient. It does NOT verify a real DNS server, the
// cgo resolver, or the egress-proxy case.
func FuzzConnectAWSResolverRebinding(f *testing.F) {
	egressref.RunRebind(f, func() egressref.DialFunc {
		return siteDial(awsSMHTTPClient())
	}, egressref.LinkLocalTier)
}
