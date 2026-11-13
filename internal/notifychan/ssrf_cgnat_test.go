package notifychan

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/netutil"
)

// V7 egress parity F2: the notification-webhook guard classified with stdlib
// ip.IsPrivate(), which excludes RFC-6598 CGNAT 100.64.0.0/10 (Alibaba Cloud
// IMDS 100.100.100.200). isDisallowedIP now delegates to the shared webhook-tier
// predicate. This pins the refusal in this package, through the classifier and
// through the netutil.Dialer it is wired into, so reverting isDisallowedIP to
// the stdlib check goes red here (the evidencesink parity harness never calls
// this package).
func TestIsDisallowedIP_RefusesCGNAT(t *testing.T) {
	dialer := netutil.Dialer{Disallow: isDisallowedIP}
	ctx := context.Background()

	for _, s := range []string{
		"100.64.0.1",             // bottom of 100.64.0.0/10
		"100.100.100.200",        // Alibaba Cloud IMDS
		"100.127.255.255",        // top of 100.64.0.0/10
		"::ffff:100.100.100.200", // IPv4-mapped
		"64:ff9b::6464:64c8",     // NAT64 well-known prefix of 100.100.100.200
	} {
		ip := net.ParseIP(s)
		require.NotNil(t, ip, s)
		assert.True(t, isDisallowedIP(ip), "%s (CGNAT) must be refused", s)
		assert.Error(t, dialer.ValidateHost(ctx, s), "dial guard must refuse %s", s)
	}
	// Green direction: the public neighbours of 100.64.0.0/10 stay allowed.
	for _, s := range []string{"100.63.255.255", "100.128.0.1"} {
		assert.False(t, isDisallowedIP(net.ParseIP(s)), "%s is outside 100.64.0.0/10 and must stay allowed", s)
		assert.NoError(t, dialer.ValidateHost(ctx, s), "dial guard must allow %s", s)
	}
}
