package netutil

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeConn is a no-op net.Conn returned by a fake Dial so tests don't open a
// real socket.
type fakeConn struct{ net.Conn }

func TestDialer_DialContext_RefusesDisallowedLiteralIP(t *testing.T) {
	var dialed string
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return &fakeConn{}, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:443")
	require.Error(t, err, "cloud IMDS literal IP must be refused")
	assert.Empty(t, dialed, "the underlying dial must never be reached")
}

func TestDialer_DialContext_AllowsPublicLiteralIP(t *testing.T) {
	var dialed string
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return &fakeConn{}, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "93.184.216.34:443")
	require.NoError(t, err)
	assert.Equal(t, "93.184.216.34:443", dialed)
}

// TestDialer_DialContext_DNSRebind is the detection_idea scenario: a hostname
// that resolves to an ALLOWED (public) address is nonetheless refused when
// (some of) its resolved addresses are private/link-local — simulating a
// DNS-rebinding attacker whose name resolves to a safe IP for a validate-once
// guard but to an internal address for the real connection. The core
// property under test is that Dialer performs its OWN resolution and
// validates it — a separate, earlier "looks safe" check elsewhere (e.g. at
// config create/update time) cannot be trusted at connect time.
func TestDialer_DialContext_DNSRebind(t *testing.T) {
	var dialed string
	rebindHost := "attacker-controlled.example"
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, host string) ([]net.IPAddr, error) {
			require.Equal(t, rebindHost, host)
			// The attacker's DNS now answers with the internal/IMDS address —
			// simulating the second, connect-time resolution of a rebinding
			// attack, distinct from whatever answer a prior validate-time
			// lookup saw.
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return &fakeConn{}, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(rebindHost, "443"))
	require.Error(t, err, "a hostname resolving to a private/link-local address at DIAL time must be refused, even though some earlier check may have seen a different, safe answer")
	assert.Contains(t, err.Error(), "disallowed address")
	assert.Empty(t, dialed, "the underlying dial must never be reached for a rebound target")
}

func TestDialer_DialContext_PinsFirstValidatedIP_NotHostname(t *testing.T) {
	var dialed string
	host := "safe.example"
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("203.0.113.10")},
				{IP: net.ParseIP("203.0.113.11")},
			}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return &fakeConn{}, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, "443"))
	require.NoError(t, err)
	// The crux of the fix: the actual dial target is the validated IP
	// literal, never the original hostname — so the connection itself cannot
	// trigger a second, independent DNS resolution.
	assert.Equal(t, "203.0.113.10:443", dialed)
}

func TestDialer_DialContext_AnyDisallowedResolvedAddressRefuses(t *testing.T) {
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			// A mix of public and private addresses: the whole host must be
			// refused, not just have the bad address silently skipped.
			return []net.IPAddr{
				{IP: net.ParseIP("203.0.113.10")},
				{IP: net.ParseIP("10.0.0.5")},
			}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			t.Fatalf("dial must not be reached, got addr %q", addr)
			return nil, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "mixed.example:443")
	require.Error(t, err)
}

func TestDialer_DialContext_ResolveErrorPropagates(t *testing.T) {
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return nil, errors.New("boom")
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "unresolvable.example:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestDialer_DialContext_NilDisallowPermitsEverything(t *testing.T) {
	var dialed string
	d := Dialer{
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return &fakeConn{}, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:443")
	require.NoError(t, err, "a Dialer with no Disallow predicate is an explicit opt-out, e.g. allow_private_network_target")
	assert.Equal(t, "169.254.169.254:443", dialed)
}

func TestDialer_DialContextTCP_DelegatesToDialContext(t *testing.T) {
	var network string
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Dial: func(_ context.Context, n, addr string) (net.Conn, error) {
			network = n
			return &fakeConn{}, nil
		},
	}
	_, err := d.DialContextTCP(context.Background(), "203.0.113.10:443")
	require.NoError(t, err)
	assert.Equal(t, "tcp", network)
}

func TestIsPrivateOrLinkLocal(t *testing.T) {
	disallowed := []string{
		"10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1",
		"169.254.169.254", "100.64.0.1", "::1", "fc00::1", "fe80::1",
	}
	for _, ip := range disallowed {
		assert.True(t, IsPrivateOrLinkLocal(net.ParseIP(ip)), "%s must be disallowed", ip)
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, ip := range allowed {
		assert.False(t, IsPrivateOrLinkLocal(net.ParseIP(ip)), "%s must be allowed", ip)
	}
}
