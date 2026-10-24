package core

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The notification-channel guard refuses loopback, but Go's net.Dial treats an
// unspecified host (0.0.0.0, ::) as the local system and Linux routes a
// connect() to 0.0.0.0 to loopback. Every check below must refuse it: the
// create/update-time validateWebhookURL, the send-time literal check, and the
// dial-time escalationTransport policy.
func TestIsChannelDisallowedIP_RefusesUnspecifiedAndThisNetwork(t *testing.T) {
	for _, s := range []string{
		"0.0.0.0",
		"::",
		"0.1.2.3",            // rest of 0.0.0.0/8
		"::ffff:0.0.0.0",     // IPv4-mapped
		"64:ff9b::0.0.0.0",   // NAT64 well-known
		"64:ff9b:1::0.0.0.0", // NAT64 local-use
	} {
		ip := net.ParseIP(s)
		require.NotNil(t, ip, s)
		assert.True(t, isChannelDisallowedIP(ip), "%s must be refused as a channel destination", s)
	}
	// Green direction: public addresses, including NAT64-embedded ones, still pass.
	for _, s := range []string{"203.0.113.7", "64:ff9b::cb00:7107", "2001:db8::1"} {
		assert.False(t, isChannelDisallowedIP(net.ParseIP(s)), "%s must stay allowed", s)
	}
}

func TestValidateWebhookURL_RefusesUnspecifiedLiteral(t *testing.T) {
	for _, u := range []string{"https://0.0.0.0/hook", "https://0.0.0.0:8443/hook", "https://[::]/hook"} {
		require.Error(t, validateWebhookURL(u), "create/update time: %s", u)
		require.Error(t, validateWebhookSendTimeURL(u), "send time: %s", u)
	}
}

// TestPostJSONToURL_UnspecifiedNeverReachesLoopback drives the production
// escalationTransport (c.httpClient nil) at a loopback listener through both an
// unspecified literal and a hostname that resolves to 0.0.0.0 at dial time, and
// asserts the effect: the listener must see no connection at all. The return
// value alone cannot tell the two apart (without the guard the dial succeeds
// and the TLS handshake then fails, which is also an error).
func TestPostJSONToURL_UnspecifiedNeverReachesLoopback(t *testing.T) {
	origResolve := channelLookupIPAddr
	t.Cleanup(func() { channelLookupIPAddr = origResolve })
	const zeroHost = "zero.escalation.example"
	channelLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		require.Equal(t, zeroHost, host)
		return []net.IPAddr{{IP: net.IPv4zero}}, nil
	}

	for _, host := range []string{"0.0.0.0", zeroHost} {
		t.Run(host, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			var accepted atomic.Int32
			var wg sync.WaitGroup
			wg.Go(func() {
				for {
					conn, aerr := ln.Accept()
					if aerr != nil {
						return
					}
					accepted.Add(1)
					_ = conn.Close()
				}
			})
			port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

			c := NewKeyorixCore(new(MockStorage))
			perr := c.postJSONToURL(t.Context(), "https://"+net.JoinHostPort(host, port)+"/hook", map[string]string{"k": "v"})

			_ = ln.Close()
			wg.Wait()
			require.Error(t, perr)
			assert.Zero(t, accepted.Load(), "the POST to %s reached a loopback listener: %v", host, perr)
		})
	}
}
