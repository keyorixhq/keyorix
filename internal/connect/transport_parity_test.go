package connect

// transport_parity_test.go — confirms newConnectHardenedTransport preserves
// each backend's own base-transport tuning (dial/TLS-handshake timeouts,
// ForceAttemptHTTP2, MaxIdleConnsPerHost, TLS trust) rather than silently
// substituting Go's generic defaults in its place. See
// docs/findings/2026-09-19-FINDING-connect-response-trust-gaps.md §5 for the
// full before/after table this documents and the reasoning behind each base
// transport constructor (vaultBaseTransport/azureBaseTransport/awsBaseTransport,
// hardened_client.go).
import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unwrapHardenedTransport peels newConnectHardenedTransport's two wrapper
// layers (targetGuardRoundTripper, sizeCappedRoundTripper) to reach the real
// *http.Transport underneath, for white-box inspection of its field values —
// legitimate here since this file is in the same package as the type under
// test, not an external consumer reaching into unexported internals.
func unwrapHardenedTransport(t *testing.T, rt http.RoundTripper) *http.Transport {
	t.Helper()
	tg, ok := rt.(targetGuardRoundTripper)
	require.True(t, ok, "newConnectHardenedTransport must return a targetGuardRoundTripper as its outermost layer")
	sc, ok := tg.Transport.(sizeCappedRoundTripper)
	require.True(t, ok, "targetGuardRoundTripper must wrap a sizeCappedRoundTripper")
	tr, ok := sc.Transport.(*http.Transport)
	require.True(t, ok, "sizeCappedRoundTripper must wrap a *http.Transport")
	return tr
}

// TestConnectHardenedTransport_ParityWithBackendDefaults asserts the actual
// field values on each backend's hardened transport, cross-checked against
// each backend's own real pre-fix default (Go's stdlib http.DefaultTransport
// for Vault; the vendored SDK's own default for Azure/AWS — see
// azureBaseTransport/awsBaseTransport's own doc comments for exactly how each
// was derived). connectGuardedDialer intentionally overrides DialContext
// uniformly across all three (see its own doc comment) — the 30s/30s
// dial-timeout/keep-alive values it sets are checked once, not per backend,
// since they're a shared constant, not something that could drift between
// backends independently.
func TestConnectHardenedTransport_ParityWithBackendDefaults(t *testing.T) {
	assert.Equal(t, 30*time.Second, connectDialTimeout, "must match all three backends' own pre-fix dial timeout (Go stdlib, azcore, aws-sdk-go-v2 all independently use 30s)")
	assert.Equal(t, 30*time.Second, connectDialKeepAlive, "must match all three backends' own pre-fix dial keep-alive (same three sources, all 30s)")

	cases := []struct {
		name                    string
		base                    *http.Transport
		wantForceHTTP2          bool
		wantTLSHandshakeTimeout time.Duration
		wantIdleConnTimeout     time.Duration
		wantMaxIdleConns        int
		// wantMaxIdleConnsPerHost: 0 means "field left at Go's zero value",
		// which net/http's Transport internally treats as
		// DefaultMaxIdleConnsPerHost (2) at request time — Vault's own
		// pre-fix http.DefaultTransport never set this field explicitly
		// either, so 0 here is the correct preserved value, not a gap.
		wantMaxIdleConnsPerHost int
	}{
		// vault: Go's own http.DefaultTransport, verified directly against
		// GOROOT's net/http/transport.go — never had any SDK-specific tuning
		// to preserve, since vault.go never used one.
		{"vault", vaultBaseTransport(), true, 10 * time.Second, 90 * time.Second, 100, 0},
		// azure: hand-replicated from azure-sdk-for-go's own unexported
		// default (azureBaseTransport's own doc comment cites the exact file).
		{"azure", azureBaseTransport(), true, 10 * time.Second, 90 * time.Second, 100, 10},
		// aws: a REAL clone of aws-sdk-go-v2's own default transport, via the
		// SDK's own exported constructor (awsBaseTransport's own doc comment).
		{"aws", awsBaseTransport(), true, 10 * time.Second, 90 * time.Second, 100, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hardened := unwrapHardenedTransport(t, newConnectHardenedTransport(tc.base))
			assert.Equal(t, tc.wantForceHTTP2, hardened.ForceAttemptHTTP2, "ForceAttemptHTTP2")
			assert.Equal(t, tc.wantTLSHandshakeTimeout, hardened.TLSHandshakeTimeout, "TLSHandshakeTimeout")
			assert.Equal(t, tc.wantIdleConnTimeout, hardened.IdleConnTimeout, "IdleConnTimeout")
			assert.Equal(t, tc.wantMaxIdleConns, hardened.MaxIdleConns, "MaxIdleConns")
			assert.Equal(t, tc.wantMaxIdleConnsPerHost, hardened.MaxIdleConnsPerHost, "MaxIdleConnsPerHost")
			// ResponseHeaderTimeout: none of the three backends' own pre-fix
			// defaults set one (confirmed by direct source read of all
			// three) -- 0 (no timeout) is the correct preserved value here,
			// not an omission.
			assert.Zero(t, hardened.ResponseHeaderTimeout, "ResponseHeaderTimeout")
			// Proxy must still be set (http.ProxyFromEnvironment or
			// equivalent) -- confirmed non-nil rather than asserting
			// function-value equality, since Go doesn't allow comparing
			// func values for equality.
			assert.NotNil(t, hardened.Proxy, "Proxy")
			// DialContext must be connectGuardedDialer's, not the base
			// transport's own original one -- this IS the one intentional
			// override, confirmed by checking it's non-nil and (implicitly)
			// wired via newConnectHardenedTransport's own assignment; the
			// link-local-refusal behavior itself is covered by
			// link_local_guard_test.go and proxy_target_guard_test.go, not
			// re-asserted here.
			assert.NotNil(t, hardened.DialContext, "DialContext")
		})
	}
}

// TestConnectHardenedTransport_PreservesCustomTLSTrust confirms
// newConnectHardenedTransport WRAPS a base transport's own TLSClientConfig
// (including a custom RootCAs pool, standing in for a private CA an operator
// has configured trust for) rather than discarding it in favor of a fresh,
// system-trust-only config.
//
// None of the three Connect backends currently expose a way for an operator
// to actually configure a custom CA or client certificate — confirmed
// exhaustively: ConnectorConfig (internal/config/config.go) has no TLS-related
// field at all, and none of vault.go/azurekv.go/awssm.go ever reads one — so
// this test demonstrates the DESIGN property (wrap, don't replace) rather than
// an existing operator-facing feature. It matters because Vault specifically
// is commonly self-hosted on-prem with an internal CA (a realistic future
// feature request); if custom-CA support is ever added there, this
// hardened-client layer must not be what silently breaks it.
func TestConnectHardenedTransport_PreservesCustomTLSTrust(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// srv.Certificate() stands in for a private CA; a base transport trusting
	// ONLY this pool (not the system pool) simulates an operator who has
	// configured trust for their own internal CA and nothing else.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	base := vaultBaseTransport()
	base.TLSClientConfig = &tls.Config{RootCAs: pool}

	rt := newConnectHardenedTransport(base)
	cl := &http.Client{Transport: rt}

	resp, err := cl.Get(srv.URL)
	require.NoError(t, err, "the hardened transport must still connect using the caller-supplied private-CA trust, not silently fall back to system-only trust")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestConnectBaseTransports_NoCustomCAConfiguredToday is the accurate CURRENT-
// STATE counterpart to TestConnectHardenedTransport_PreservesCustomTLSTrust
// above: machine-checks that none of the three base-transport constructors
// set a custom RootCAs or client certificate today — i.e. all three currently
// use the system trust store, unchanged from each backend's own pre-fix
// behavior (which also never set one). If this test ever needs updating
// because a base transport constructor started setting TLSClientConfig.RootCAs,
// that's a deliberate operator-facing feature landing, not an accidental
// regression — the distinction matters for whoever next touches this file.
func TestConnectBaseTransports_NoCustomCAConfiguredToday(t *testing.T) {
	bases := map[string]*http.Transport{
		"vault": vaultBaseTransport(),
		"azure": azureBaseTransport(),
		"aws":   awsBaseTransport(),
	}
	for name, base := range bases {
		t.Run(name, func(t *testing.T) {
			if base.TLSClientConfig == nil {
				return // nil -> Go's own system-default trust; explicitly fine
			}
			assert.Nil(t, base.TLSClientConfig.RootCAs, "no operator-facing config exists to derive a custom RootCAs pool from")
			assert.Nil(t, base.TLSClientConfig.Certificates, "no operator-facing config exists to derive a client certificate from")
		})
	}
}
