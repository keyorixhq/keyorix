// egress_site_fuzz_test.go — V7-GAP-1: site-wiring parity for the Connect backends.
//
// Every Connect HTTP backend (Vault, Azure Key Vault, AWS Secrets Manager) gets its
// transport from newConnectHardenedTransport(<backend base>). The guard is the
// DialContext that function installs; a backend whose constructor passes a bare base
// transport to its SDK instead would be unguarded and every netutil test would stay
// green. These targets build the real hardened transport for each backend base and dial
// through it.
//
// Policy: link-local only, in every encoding (documented residual: fd00:ec2::254 and
// the other metadata addresses outside 169.254/16 are permitted; netutil/dialer.go).
package connect

import (
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

// hardenedDial unwraps newConnectHardenedTransport's wrapper chain
// (targetGuardRoundTripper -> sizeCappedRoundTripper -> *http.Transport) to the
// transport whose DialContext the SDK's connections actually use.
func hardenedDial(base *http.Transport) egressref.DialFunc {
	tg, ok := newConnectHardenedTransport(base).(targetGuardRoundTripper)
	if !ok {
		panic("newConnectHardenedTransport no longer returns a targetGuardRoundTripper; update this target")
	}
	sc, ok := tg.Transport.(sizeCappedRoundTripper)
	if !ok {
		panic("targetGuardRoundTripper no longer wraps a sizeCappedRoundTripper; update this target")
	}
	tr, ok := sc.Transport.(*http.Transport)
	if !ok {
		panic("sizeCappedRoundTripper no longer wraps an *http.Transport; update this target")
	}
	return tr.DialContext
}

func FuzzConnectVaultTransportEgressParity(f *testing.F) {
	egressref.Run(f, "connect.vault", func() egressref.DialFunc {
		return hardenedDial(vaultBaseTransport())
	}, egressref.LinkLocalTier)
}

func FuzzConnectAzureTransportEgressParity(f *testing.F) {
	egressref.Run(f, "connect.azure", func() egressref.DialFunc {
		return hardenedDial(azureBaseTransport())
	}, egressref.LinkLocalTier)
}

func FuzzConnectAWSTransportEgressParity(f *testing.F) {
	base := awsBaseTransportOrNil()
	if base == nil {
		f.Skip("noaws build: no AWS backend transport")
	}
	egressref.Run(f, "connect.aws", func() egressref.DialFunc {
		return hardenedDial(base)
	}, egressref.LinkLocalTier)
}
