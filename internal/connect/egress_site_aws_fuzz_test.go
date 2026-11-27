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
