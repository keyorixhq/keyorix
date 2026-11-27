package connect

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/egressref"
)

// bypassRecorder is an egressref.TB that records a Fatalf instead of aborting.
type bypassRecorder struct{ failures []string }

func (r *bypassRecorder) Helper() {}
func (r *bypassRecorder) Fatalf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// probeIMDS dials 169.254.169.254 in every encoding through c the way the
// FuzzConnect*TransportEgressParity targets do.
func probeIMDS(c *http.Client) *bypassRecorder {
	r := &bypassRecorder{}
	for kind := range byte(egressref.Kinds) {
		a := egressref.Decode(kind, 169, 254, 169, 254)
		egressref.Probe(r, "wiring", siteDial(c), a, "443", "", egressref.LinkLocalTier(a))
	}
	return r
}

// TestSiteDialTurnsRedOnUnhardenedWiring is the red proof for the Connect site-wiring
// targets: it builds the client a backend would build if its call site dropped
// newConnectHardenedTransport (the bare base, with or without the Azure error-body
// scrub, or no transport at all) and shows that siteDial plus the oracle reports a
// BYPASS for it, while the hardened transport over the same base stays green. Without
// this, siteDial could unwrap to some other dialer and the targets would pass vacuously.
func TestSiteDialTurnsRedOnUnhardenedWiring(t *testing.T) {
	bases := map[string]func() *http.Transport{"vault": vaultBaseTransport, "azure": azureBaseTransport}
	if aws := awsBaseTransportOrNil(); aws != nil {
		bases["aws"] = func() *http.Transport { return aws.Clone() }
	}
	for name, base := range bases {
		for shape, c := range map[string]*http.Client{
			"bare base":                {Transport: base()},
			"scrub over the bare base": {Transport: errorBodyScrubRoundTripper{Transport: base()}},
			"size cap over bare base":  {Transport: sizeCappedRoundTripper{Transport: base(), MaxBytes: connectMaxResponseBytes}},
			"no transport (stdlib)":    {},
		} {
			if r := probeIMDS(c); len(r.failures) == 0 {
				t.Errorf("%s, %s: the oracle stayed green on an unguarded client", name, shape)
			}
		}
		for shape, c := range map[string]*http.Client{
			"hardened":       {Transport: newConnectHardenedTransport(base())},
			"azure hardened": {Transport: newAzureHardenedTransport(base())},
		} {
			if r := probeIMDS(c); len(r.failures) != 0 {
				t.Errorf("%s, %s: the oracle must stay green on the hardened client: %v", name, shape, r.failures)
			}
		}
	}
}

// TestVaultConnectorClientIsHardened pins the one Connect client a test can build
// without SDK credentials: NewVaultConnector's.
func TestVaultConnectorClientIsHardened(t *testing.T) {
	if r := probeIMDS(NewVaultConnector("v", "https://vault.example.test", "t", nil).client); len(r.failures) != 0 {
		t.Fatalf("NewVaultConnector's client let a link-local address through: %v", r.failures)
	}
}
