// egress_guard_test.go — direct behavioral coverage for the SIEM forwarder's
// egress guard (2b/2d): before this fix, newForwarder built a bare
// http.Transport with NO SSRF or TLS enforcement of any kind -- an
// operator-configured Endpoint pointing at a private/internal host, or using
// plain http://, went through completely unchecked. These tests exercise
// newForwarder's own validation directly (network-free: the checks run
// before any request is ever sent), plus the dial-time IP re-validation via
// a fake resolver (mirroring internal/dynamic's dialResolve test pattern),
// never a real DNS query.
package siem

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewForwarder_RefusesPrivateNetworkTargetByDefault(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = func(_ context.Context, host string) ([]net.IPAddr, error) {
		require.Equal(t, "internal-siem.example.net", host)
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	}

	f, err := newForwarder(Config{
		Enabled:  true,
		Provider: ProviderWebhook,
		Endpoint: "https://internal-siem.example.net/collect",
	}, defaultBaseBackoff)
	require.NoError(t, err, "construction succeeds -- the SSRF guard is dial-time, not construction-time")
	t.Cleanup(f.Close)

	_, sendErr := f.send(context.Background(), sampleEvent())
	require.Error(t, sendErr, "a private-network resolved target must be refused at dial time")
	assert.Contains(t, sendErr.Error(), "disallowed address")
}

func TestNewForwarder_AllowPrivateNetworkTargetOptsOut(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	}

	f, err := newForwarder(Config{
		Enabled: true, Provider: ProviderWebhook,
		// Port 1 (nothing listening) so send() still fails -- the point is
		// that it must NOT fail via the private-network guard.
		Endpoint:                  "https://internal-siem.example.net:1/collect",
		AllowPrivateNetworkTarget: true,
	}, defaultBaseBackoff)
	require.NoError(t, err)
	t.Cleanup(f.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, sendErr := f.send(ctx, sampleEvent())
	require.Error(t, sendErr, "still fails -- nothing is listening -- but NOT via the private-network guard")
	assert.NotContains(t, sendErr.Error(), "disallowed address")
}

func TestNewForwarder_LoopbackTargetPermittedWithoutOptOut(t *testing.T) {
	f, err := newForwarder(Config{
		Enabled:  true,
		Provider: ProviderWebhook,
		Endpoint: "http://127.0.0.1:1/collect",
	}, defaultBaseBackoff)
	require.NoError(t, err, "http on loopback must be permitted without any opt-out (matches evidencesink/notifychan convention)")
	t.Cleanup(f.Close)
}

func TestNewForwarder_RefusesPlaintextNonLoopbackByDefault(t *testing.T) {
	_, err := newForwarder(Config{
		Enabled:  true,
		Provider: ProviderWebhook,
		Endpoint: "http://siem.example.net/collect",
	}, defaultBaseBackoff)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use TLS")
}

func TestNewForwarder_AllowInsecureTransportOptsOut(t *testing.T) {
	f, err := newForwarder(Config{
		Enabled:                true,
		Provider:               ProviderWebhook,
		Endpoint:               "http://siem.example.net/collect",
		AllowInsecureTransport: true,
	}, defaultBaseBackoff)
	require.NoError(t, err, "the explicit opt-out must permit a plaintext non-loopback endpoint")
	t.Cleanup(f.Close)
}
