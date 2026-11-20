package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenCIDRAllowlist_IPv4MappedEntryIsTheIPv4Host is #4520's sibling in the PAT
// and machine-token network allowlists: EncodePATCIDRs appended "/32" to the input
// text of a bare "::ffff:1.2.3.4", storing the IPv6 network ::/32, so the token was
// refused from 1.2.3.4 and accepted from ::1 and every other ::/32 address (a
// widened restriction). New entries are stored as the IPv4 host, and a row already
// stored in the old shape is read as the IPv4 host too.
func TestTokenCIDRAllowlist_IPv4MappedEntryIsTheIPv4Host(t *testing.T) {
	t.Parallel()

	enc, err := encodePATCIDRs([]string{"::ffff:1.2.3.4"})
	require.NoError(t, err)
	stored := DecodePATCIDRs(enc)
	assert.True(t, IPInCIDRs("1.2.3.4", stored), "the intended host is allowed (stored %v)", stored)
	assert.False(t, IPInCIDRs("::1", stored), "::1 is not in the allowlist (stored %v)", stored)

	legacy := []string{"::ffff:1.2.3.4/32"} // the text the old encoder stored
	assert.True(t, IPInCIDRs("1.2.3.4", legacy))
	assert.False(t, IPInCIDRs("::1", legacy), "a legacy row must not admit ::/32")
	assert.False(t, IPInCIDRs("::2", legacy))

	_, err = encodePATCIDRs([]string{"::ffff:1.2.3.4/64"})
	assert.Error(t, err, "a mapped prefix with no IPv4 meaning is refused")
	assert.False(t, IPInCIDRs("::1", []string{"::ffff:1.2.3.4/64"}), "and skipped when read (fail closed)")

	// Positive controls: ordinary IPv4 and IPv6 entries behave as before.
	assert.True(t, IPInCIDRs("10.1.2.3", []string{"10.0.0.0/8"}))
	assert.True(t, IPInCIDRs("2001:db8::7", []string{"2001:db8::/32"}))
	assert.True(t, IPInCIDRs("1.2.3.4", []string{"::ffff:1.2.3.4/128"}), "a mapped /128 is that host")
}
