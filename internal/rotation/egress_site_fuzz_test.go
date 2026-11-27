// egress_site_fuzz_test.go — V7-GAP-1: site-wiring parity for the Microsoft Graph
// rotation client. The Graph host is a compiled constant, so the only attacker-reachable
// input is a hostile redirect or a proxy; the transport still carries a link-local dial
// guard (H1) and this target keeps it carried in every address encoding.
//
// Policy: link-local only (see internal/fuzzutil/egressref).
package rotation

import (
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

func FuzzAzureGraphTransportEgressParity(f *testing.F) {
	egressref.Run(f, "rotation.azureGraphHTTPClient",
		func() egressref.DialFunc {
			return azureGraphHTTPClient().Transport.(*http.Transport).DialContext
		},
		egressref.LinkLocalTier)
}

// FuzzAzureGraphResolverRebinding drives a hostname through the stdlib resolver (an
// in-process DNS stub, see egressref.RebindDNS) whose answer changes after the first
// lookup, and dials it through the same client. It does NOT verify a real DNS server,
// the cgo resolver, or the egress-proxy case (the dial then targets the proxy).
func FuzzAzureGraphResolverRebinding(f *testing.F) {
	egressref.RunRebind(f, func() egressref.DialFunc {
		return azureGraphHTTPClient().Transport.(*http.Transport).DialContext
	}, egressref.LinkLocalTier)
}
