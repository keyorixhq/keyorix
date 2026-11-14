package core

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// V7 egress parity F2: the notification-channel guard used a hand-rolled stdlib
// check that did not cover RFC-6598 CGNAT 100.64.0.0/10 (Alibaba Cloud IMDS
// 100.100.100.200). isChannelDisallowedIP now delegates to
// netutil.IsPrivateOrLinkLocal. FuzzSSRFGuardDifferential only checks that
// encodings agree with the raw form, so it stays green on a revert; this test
// pins the refusal itself, at the classifier and at validateWebhookURL (literal
// and resolved hostname).
func TestIsChannelDisallowedIP_RefusesCGNAT(t *testing.T) {
	for _, s := range []string{
		"100.64.0.1",             // bottom of 100.64.0.0/10
		"100.100.100.200",        // Alibaba Cloud IMDS
		"100.127.255.255",        // top of 100.64.0.0/10
		"::ffff:100.100.100.200", // IPv4-mapped
		"64:ff9b::6464:64c8",     // NAT64 well-known prefix of 100.100.100.200
	} {
		ip := net.ParseIP(s)
		require.NotNil(t, ip, s)
		assert.True(t, isChannelDisallowedIP(ip), "%s (CGNAT) must be refused as a channel destination", s)
	}
	// Green direction: the public neighbours of 100.64.0.0/10 stay allowed.
	for _, s := range []string{"100.63.255.255", "100.128.0.1"} {
		assert.False(t, isChannelDisallowedIP(net.ParseIP(s)), "%s is outside 100.64.0.0/10 and must stay allowed", s)
	}
}

func TestValidateWebhookURL_RefusesCGNAT(t *testing.T) {
	for _, u := range []string{
		"https://100.100.100.200/x",
		"https://100.64.0.1:8443/x",
		"https://[64:ff9b::6464:64c8]/x",
	} {
		assert.Error(t, validateWebhookURL(u), "%s must be refused", u)
		assert.Error(t, validateWebhookSendTimeURL(u), "%s must be refused at send time", u)
	}

	orig := channelLookupIPAddr
	t.Cleanup(func() { channelLookupIPAddr = orig })
	channelLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host == "imds.cgnat.example" {
			return []net.IPAddr{{IP: net.ParseIP("100.100.100.200")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("100.128.0.1")}}, nil
	}
	assert.Error(t, validateWebhookURL("https://imds.cgnat.example/x"), "a hostname resolving to CGNAT must be refused")
	assert.NoError(t, validateWebhookURL("https://public.example/x"), "a hostname resolving outside 100.64.0.0/10 must pass")
	assert.NoError(t, validateWebhookURL("https://100.128.0.1/x"), "a literal outside 100.64.0.0/10 must pass")
}
