// egress_site_fuzz_test.go — V7-GAP-1: site-wiring parity for the Connect backends.
//
// Every Connect HTTP backend (Vault, Azure Key Vault, AWS Secrets Manager) gets its
// transport from newConnectHardenedTransport(<backend base>). The guard is the
// DialContext that function installs; a backend whose constructor passes a bare base
// transport to its SDK instead would be unguarded and every netutil test would stay
// green. These targets take the transport from the client each backend really builds
// (NewVaultConnector's client, azureKVHTTPClient, awsSMHTTPClient) and dial through it,
// so dropping the hardening at one of those call sites turns its target red as BYPASS.
// The Azure and AWS targets live in their own build-tagged files.
//
// Policy: link-local only, in every encoding (documented residual: fd00:ec2::254 and
// the other metadata addresses outside 169.254/16 are permitted; netutil/dialer.go).
package connect

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

// siteDial peels the hardened wrapper chain (errorBodyScrubRoundTripper ->
// targetGuardRoundTripper -> sizeCappedRoundTripper) off a backend client's transport
// down to the *http.Transport whose DialContext the SDK's connections actually use. A
// layer that is missing is skipped rather than required: a site that hands its SDK the
// bare base transport reaches the base's own dialer, and the oracle reports BYPASS.
func siteDial(c *http.Client) egressref.DialFunc {
	rt := c.Transport
	for {
		switch v := rt.(type) {
		case errorBodyScrubRoundTripper:
			rt = v.Transport
		case targetGuardRoundTripper:
			rt = v.Transport
		case sizeCappedRoundTripper:
			rt = v.Transport
		case *http.Transport:
			if v.DialContext == nil {
				// What net/http itself uses for a nil DialContext.
				return (&net.Dialer{}).DialContext
			}
			return v.DialContext
		case nil:
			// http.DefaultTransport, which has no dial guard.
			return http.DefaultTransport.(*http.Transport).DialContext
		default:
			panic(fmt.Sprintf("unknown RoundTripper %T in a Connect client; teach siteDial to unwrap it", rt))
		}
	}
}

func FuzzConnectVaultTransportEgressParity(f *testing.F) {
	egressref.Run(f, "connect.vault", func() egressref.DialFunc {
		return siteDial(NewVaultConnector("v", "https://vault.example.test", "t", nil).client)
	}, egressref.LinkLocalTier)
}
