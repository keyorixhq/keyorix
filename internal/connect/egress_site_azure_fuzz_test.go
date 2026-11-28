//go:build !noazure

package connect

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

// FuzzConnectAzureTransportEgressParity dials through azureKVHTTPClient, the client
// azurekv.go's client() hands to azsecrets (egress_site_fuzz_test.go).
func FuzzConnectAzureTransportEgressParity(f *testing.F) {
	egressref.Run(f, "connect.azure", func() egressref.DialFunc {
		return siteDial(azureKVHTTPClient())
	}, egressref.LinkLocalTier)
}

// FuzzConnectAzureResolverRebinding drives a hostname through the stdlib resolver (an
// in-process DNS stub, see egressref.RebindDNS) whose answer changes after the first
// lookup, and dials it through azureKVHTTPClient. It does NOT verify a real DNS server,
// the cgo resolver, or the egress-proxy case.
func FuzzConnectAzureResolverRebinding(f *testing.F) {
	egressref.RunRebind(f, func() egressref.DialFunc {
		return siteDial(azureKVHTTPClient())
	}, egressref.LinkLocalTier)
}
