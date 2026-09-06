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

func TestDialer_DialContext_InvalidAddressReturnsError(t *testing.T) {
	d := Dialer{Disallow: IsPrivateOrLinkLocal}
	_, err := d.DialContext(context.Background(), "tcp", "not-a-valid-host-port")
	require.Error(t, err, "an addr with no port must fail SplitHostPort")
	assert.Contains(t, err.Error(), "invalid dial address")
}

func TestDialer_DialContext_EmptyResolvedAddressesReturnsError(t *testing.T) {
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return nil, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			t.Fatalf("dial must not be reached, got addr %q", addr)
			return nil, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "no-addrs.example:443")
	require.Error(t, err, "a hostname that resolves to zero addresses must be refused, not silently pass through")
	assert.Contains(t, err.Error(), "did not resolve to any address")
}

func TestDialer_DialContext_NilDialDefaultsToNetDialer(t *testing.T) {
	// No Dial field set: DialContext must fall back to (&net.Dialer{}).DialContext
	// rather than panicking on a nil func. Dialing a closed local listener lets
	// us observe the real dialer actually attempted a connection (and failed,
	// as expected) without depending on outbound network access.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close(), "close immediately so the port is refusing connections")

	d := Dialer{} // Disallow nil too: exercises the zero-value Dialer end to end.
	_, dialErr := d.DialContext(context.Background(), "tcp", addr)
	require.Error(t, dialErr, "connecting to a closed local port via the real net.Dialer must fail")
}

func TestDialer_DialContext_NilResolveDefaultsToDefaultResolver(t *testing.T) {
	// No Resolve field set: DialContext must fall back to DefaultResolver
	// (real DNS/hosts-file resolution) rather than a nil-func panic. Disallow
	// is nil too, so any address localhost resolves to is permitted, and we
	// only assert the dial was actually reached with a pinned IP:port.
	var dialed string
	d := Dialer{
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			return &fakeConn{}, nil
		},
	}
	_, err := d.DialContext(context.Background(), "tcp", "localhost:443")
	require.NoError(t, err)
	assert.NotEmpty(t, dialed)
	dialedHost, dialedPort, splitErr := net.SplitHostPort(dialed)
	require.NoError(t, splitErr)
	assert.Equal(t, "443", dialedPort)
	assert.NotNil(t, net.ParseIP(dialedHost), "dialed host must be a resolved IP literal, not the original hostname")
}

func TestDefaultResolver_ResolvesLoopback(t *testing.T) {
	addrs, err := DefaultResolver(context.Background(), "localhost")
	require.NoError(t, err)
	require.NotEmpty(t, addrs, "localhost must resolve to at least one address")
	found := false
	for _, a := range addrs {
		if a.IP.IsLoopback() {
			found = true
			break
		}
	}
	assert.True(t, found, "localhost must resolve to a loopback address, got %v", addrs)
}

func TestDialer_ValidateHost_LiteralIPAllowed(t *testing.T) {
	d := Dialer{Disallow: IsPrivateOrLinkLocal}
	require.NoError(t, d.ValidateHost(context.Background(), "93.184.216.34"))
}

func TestDialer_ValidateHost_LiteralIPRefused(t *testing.T) {
	d := Dialer{Disallow: IsPrivateOrLinkLocal}
	err := d.ValidateHost(context.Background(), "169.254.169.254")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed address")
}

func TestDialer_ValidateHost_ResolvesAndValidatesEveryAddress(t *testing.T) {
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, host string) ([]net.IPAddr, error) {
			require.Equal(t, "srv-target.example.net", host)
			return []net.IPAddr{
				{IP: net.ParseIP("203.0.113.10")},
				{IP: net.ParseIP("10.0.0.5")},
			}, nil
		},
	}
	err := d.ValidateHost(context.Background(), "srv-target.example.net")
	require.Error(t, err, "a mix of public and private addresses must refuse the whole host")
	assert.Contains(t, err.Error(), "disallowed address")
}

func TestDialer_ValidateHost_DoesNotDial(t *testing.T) {
	d := Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			t.Fatalf("ValidateHost must never dial, got addr %q", addr)
			return nil, nil
		},
	}
	require.NoError(t, d.ValidateHost(context.Background(), "safe.example"))
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
