// egress_site_fuzz_test.go — V7-GAP-1: site-wiring parity for the Azure Key Vault KMS
// transport, the one link-local-tier-or-stricter site with a resolver seam
// (azureKMSResolve).
//
// FuzzAzureKMSTransportEgressParity dials literals through the real transport with the
// PRIVATE tier policy (loopback, RFC-1918, CGNAT, ULA and link-local all refused, in
// every encoding).
//
// FuzzAzureKMSResolverRebinding drives a hostname through a stub resolver whose answer
// changes after the first call (DNS rebinding): the guard must decide from the first
// answer set alone, resolve once per dial, and refuse when ANY answer in it is private.
package azurekms

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

func FuzzAzureKMSTransportEgressParity(f *testing.F) {
	egressref.Run(f, "azurekms.azureKMSTransport", func() egressref.DialFunc {
		return azureKMSTransport.Transport.(*http.Transport).DialContext
	}, egressref.PrivateTier)
}

func FuzzAzureKMSResolverRebinding(f *testing.F) {
	f.Add(byte(0), byte(8), byte(8), byte(8), byte(8), byte(0), byte(169), byte(254), byte(169), byte(254)) // public, then IMDS on re-resolve
	f.Add(byte(0), byte(8), byte(8), byte(8), byte(8), byte(2), byte(169), byte(254), byte(169), byte(254)) // mixed answer set: public + NAT64 IMDS; public + IPv4-mapped public
	f.Add(byte(0), byte(10), byte(0), byte(0), byte(1), byte(0), byte(8), byte(8), byte(8), byte(8))        // private first
	f.Add(byte(2), byte(8), byte(8), byte(8), byte(8), byte(1), byte(8), byte(8), byte(4), byte(4))         // NAT64 public + mapped public

	f.Fuzz(func(t *testing.T, k1, a1, b1, c1, d1, k2, a2, b2, c2, d2 byte) {
		first := egressref.Decode(k1, a1, b1, c1, d1)
		second := egressref.Decode(k2, a2, b2, c2, d2)

		orig := azureKMSResolve
		defer func() { azureKMSResolve = orig }()
		calls := 0
		azureKMSResolve = func(_ context.Context, _ string) ([]net.IPAddr, error) {
			calls++
			if calls == 1 {
				// The first answer set carries BOTH decoded addresses: a mixed
				// public/private answer must be refused as a whole.
				return []net.IPAddr{{IP: first.IP}, {IP: second.IP}}, nil
			}
			return []net.IPAddr{{IP: egressref.Decode(0, 169, 254, 169, 254).IP}}, nil
		}

		dial := azureKMSTransport.Transport.(*http.Transport).DialContext
		egressref.CheckResolved(t, dial, "vault.example.vault.azure.net",
			func() int { return calls }, []egressref.Addr{first, second}, egressref.PrivateTier)
	})
}
