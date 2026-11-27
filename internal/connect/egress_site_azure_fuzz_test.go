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
