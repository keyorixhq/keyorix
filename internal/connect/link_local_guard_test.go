package connect

// link_local_guard_test.go — regression tests for validateConnectorAddressNotLinkLocal
// (hardened_client.go): a Vault or Azure Key Vault connector configured with a
// link-local address — including cloud instance-metadata (169.254.169.254) — must
// be refused before any network dial is attempted, in any of the encodings
// netutil.IsLinkLocal now recognizes (raw IPv4/IPv6, and NAT64/IPv4-compatible
// IPv6 embeddings). AWS has no configurable address (see
// docs/findings/2026-09-19-FINDING-connect-response-trust-gaps.md §2) and GCP is
// unaffected by this round's fix, so neither has an equivalent test here.
//
// This covers the REGISTRATION-time literal-IP check specifically. The
// per-dial, hostname-resolves-to-link-local enforcement (the DNS-rebinding case
// connectGuardedDialer's netutil.Dialer closes) reuses netutil.Dialer directly
// and is already covered by netutil's own TestIsLinkLocal_DialerRefusesIMDSAllowsPrivate
// — no need to duplicate that wiring test here.
//
// TestValidateConnectorAddressNotLinkLocal below is the one that's actually
// red-proofed for this component: it calls validateConnectorAddressNotLinkLocal
// directly, isolated from GetSecret's full call graph. The GetSecret-level
// tests that follow it are integration confirmation that the function is
// actually WIRED IN (both return in ~0s with a "link-local"-worded error,
// proving the check fires before any network attempt) -- but red-proofing
// them independently by disabling ONLY the registration-time call turned out
// to be a confound, not a clean signal: for Vault, connectGuardedDialer's
// per-dial netutil.Dialer (still active, defense-in-depth) catches the SAME
// address at dial time instead, with netutil's own wording, not "link-local"
// -- a genuinely good finding (both layers work independently), but it means
// disabling ONLY this function doesn't reliably reproduce as this specific
// test going red. The direct unit test below doesn't have that problem.
import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConnectorAddressNotLinkLocal(t *testing.T) {
	mustReject := []struct{ name, address string }{
		{"raw IPv4 IMDS", "http://169.254.169.254:1234"},
		{"raw IPv4 link-local", "http://169.254.1.1:8200"},
		{"IPv6 link-local", "http://[fe80::1]:8200"},
		{"NAT64-encoded IMDS", "http://[64:ff9b::a9fe:a9fe]:8200"},
		{"IPv4-compatible-encoded IMDS", "http://[::a9fe:a9fe]:8200"},
	}
	for _, tc := range mustReject {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConnectorAddressNotLinkLocal("test-backend", tc.address)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "link-local")
		})
	}

	mustAllow := []struct{ name, address string }{
		{"RFC-1918", "http://10.0.0.5:8200"},
		{"loopback", "http://127.0.0.1:8200"},
		{"public hostname", "https://vault.example.com:8200"},
		{"NAT64-encoded RFC-1918", "http://[64:ff9b::a00:1]:8200"},
	}
	for _, tc := range mustAllow {
		t.Run(tc.name, func(t *testing.T) {
			assert.NoError(t, validateConnectorAddressNotLinkLocal("test-backend", tc.address))
		})
	}
}

func TestVaultConnector_RefusesLinkLocalAddress(t *testing.T) {
	cases := []struct {
		name    string
		address string
	}{
		{"raw IPv4 IMDS", "http://169.254.169.254:1234"},
		{"raw IPv4 link-local", "http://169.254.1.1:8200"},
		{"IPv6 link-local", "http://[fe80::1]:8200"},
		{"NAT64-encoded IMDS", "http://[64:ff9b::a9fe:a9fe]:8200"},
		{"IPv4-compatible-encoded IMDS", "http://[::a9fe:a9fe]:8200"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewVaultConnector("v", tc.address, "tok", nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err := c.GetSecret(ctx, "secret/data/x")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "link-local", "must be refused by the link-local guard, not fail for some other reason (e.g. a real dial timeout)")
		})
	}
}

func TestAzureKVConnector_RefusesLinkLocalAddress(t *testing.T) {
	cases := []struct {
		name    string
		address string
	}{
		{"raw IPv4 IMDS", "https://169.254.169.254:1234"},
		{"raw IPv4 link-local", "https://169.254.1.1:8443"},
		{"IPv6 link-local", "https://[fe80::1]:8443"},
		{"NAT64-encoded IMDS", "https://[64:ff9b::a9fe:a9fe]:8443"},
		{"IPv4-compatible-encoded IMDS", "https://[::a9fe:a9fe]:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewAzureKeyVaultConnector("az", tc.address, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err := c.GetSecret(ctx, "secret")
			require.Error(t, err)
			assert.True(t, strings.Contains(err.Error(), "link-local"),
				"must be refused by the link-local guard, not fail for some other reason (e.g. a real dial timeout): %v", err)
		})
	}
}

// TestVaultConnector_AllowsGenuinelyPrivateAddress is the contrast case: a
// genuinely private/on-prem address (RFC-1918, not link-local) must NOT be
// refused by this guard — the whole point of narrowing to IsLinkLocal rather
// than IsPrivateOrLinkLocal (§5 of the findings doc). Uses an address nothing
// listens on, on a short deadline, so the assertion is "not rejected by the
// link-local guard specifically" (a network-level error is expected and fine)
// rather than "the call succeeds".
func TestVaultConnector_AllowsGenuinelyPrivateAddress(t *testing.T) {
	c := NewVaultConnector("v", "http://10.255.255.1:8200", "tok", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := c.GetSecret(ctx, "secret/data/x")
	require.Error(t, err) // nothing listens there, but NOT via the link-local guard
	assert.NotContains(t, err.Error(), "link-local")
}
