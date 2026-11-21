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
// widened restriction). New entries are stored as the IPv4 host, and a row stored in
// exactly that old shape (mapped /32) is read as the IPv4 host; no other stored row
// is reinterpreted in a way that could widen it.
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

	// A legacy mapped row with any other short prefix is NOT widened: as stored,
	// "::ffff:10.0.0.0/8" was ::/8 and admitted no IPv4 client, so reading it as
	// 10.0.0.0/8 would let in clients the token refused. It is skipped (fail closed).
	assert.False(t, IPInCIDRs("10.9.9.9", []string{"::ffff:10.0.0.0/8"}), "legacy mapped /8 must not widen to 10.0.0.0/8")
	assert.False(t, IPInCIDRs("10.9.9.9", []string{"::ffff:0.0.0.0/0"}), "legacy mapped /0 must not widen to all IPv4")
	// A NEW mapped entry with a short prefix is stored as the IPv4 network it names.
	enc8, err := encodePATCIDRs([]string{"::ffff:10.0.0.0/8"})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8"}, DecodePATCIDRs(enc8))

	// IPv6 forms with a dotted tail that are not IPv4-mapped are unchanged (NAT64,
	// documentation prefix): accepted, stored as written, matched as IPv6.
	for _, c := range []string{"64:ff9b::1.2.3.4/96", "2001:db8::1.2.3.4/64", "64:ff9b::/32"} {
		e, err := encodePATCIDRs([]string{c})
		require.NoError(t, err, c)
		assert.Equal(t, []string{c}, DecodePATCIDRs(e), c)
	}
	assert.True(t, IPInCIDRs("2001:db8::7", []string{"2001:db8::1.2.3.4/64"}))
	assert.True(t, IPInCIDRs("64:ff9b::a01:203", []string{"64:ff9b::1.2.3.4/96"}))

	// Positive controls: ordinary IPv4 and IPv6 entries behave as before.
	assert.True(t, IPInCIDRs("10.1.2.3", []string{"10.0.0.0/8"}))
	assert.True(t, IPInCIDRs("2001:db8::7", []string{"2001:db8::/32"}))
	assert.True(t, IPInCIDRs("1.2.3.4", []string{"::ffff:1.2.3.4/128"}), "a mapped /128 is that host")
}
