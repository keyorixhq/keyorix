package core

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
)

func TestIPInCIDRs(t *testing.T) {
	cidrs := []string{"10.0.0.0/8", "192.0.2.4/32", "2001:db8::/32"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},      // inside 10/8
		{"192.0.2.4", true},     // exact /32
		{"192.0.2.5", false},    // adjacent to the /32
		{"203.0.113.9", false},  // outside all
		{"2001:db8::1", true},   // inside the v6 block
		{"2001:dead::1", false}, // outside the v6 block
		{"not-an-ip", false},    // unparseable → fail closed
		{"", false},             // empty → fail closed
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, IPInCIDRs(c.ip, cidrs), "ip=%s", c.ip)
	}
	// An empty allowlist passed as a gate denies (fail closed); callers only invoke it
	// when the token actually carries an allowlist.
	assert.False(t, IPInCIDRs("10.1.2.3", nil))
	// A malformed CIDR in the list is skipped, not fatal.
	assert.True(t, IPInCIDRs("10.1.2.3", []string{"garbage", "10.0.0.0/8"}))
}

func TestEncodePATCIDRs(t *testing.T) {
	// Valid CIDRs + a bare IP (promoted to a host route), deduped.
	enc, err := encodePATCIDRs([]string{"10.0.0.0/8", " 192.0.2.4 ", "10.0.0.0/8", ""})
	assert.NoError(t, err)
	got := DecodePATCIDRs(enc)
	assert.ElementsMatch(t, []string{"10.0.0.0/8", "192.0.2.4/32"}, got)

	// All-blank encodes to "" (no restriction).
	enc, err = encodePATCIDRs([]string{"", "  "})
	assert.NoError(t, err)
	assert.Equal(t, "", enc)
	assert.Nil(t, DecodePATCIDRs(enc))

	// An invalid CIDR is rejected at creation.
	_, err = encodePATCIDRs([]string{"10.0.0.0/8", "not-a-cidr"})
	assert.Error(t, err)
}

func TestPATRestrictionFrom_IncludesCIDRs(t *testing.T) {
	// A token with ONLY a CIDR allowlist (no scope/project) still yields a restriction.
	enc, _ := encodePATCIDRs([]string{"10.0.0.0/8"})
	r := patRestrictionFrom(&models.PersonalAccessToken{AllowedCIDRs: enc})
	if assert.NotNil(t, r) {
		assert.Equal(t, []string{"10.0.0.0/8"}, r.AllowedCIDRs)
	}
	// A fully-unrestricted token yields nil.
	assert.Nil(t, patRestrictionFrom(&models.PersonalAccessToken{}))
}

// TestDecodePATCIDRs_CorruptionFailsClosed verifies that a non-empty but
// unparseable allowed_cidrs column returns the sentinel (not nil), ensuring
// the PAT is denied from all networks rather than silently widened to global
// network access (#r125-H1 — the scope-corruption fix DecodePATScopes received
// in r124 missed its CIDR sibling).
func TestDecodePATCIDRs_CorruptionFailsClosed(t *testing.T) {
	// A parseable empty column yields nil (no restriction — expected).
	assert.Nil(t, DecodePATCIDRs(""))
	assert.Nil(t, DecodePATCIDRs("   "))

	// A valid JSON array parses normally.
	got := DecodePATCIDRs(`["10.0.0.0/8"]`)
	assert.Equal(t, []string{"10.0.0.0/8"}, got)

	// A non-empty but corrupted column must fail CLOSED (sentinel, not nil).
	corrupted := DecodePATCIDRs(`{not valid json}`)
	assert.Equal(t, patCIDRCorrupted, corrupted,
		"corrupted CIDR column must return the sentinel, not nil (fail-open)")

	// The sentinel must deny ALL source IPs — IPInCIDRs must return false
	// for any real address when the sentinel is in the allowlist.
	assert.False(t, IPInCIDRs("10.1.2.3", corrupted),
		"sentinel must deny a private-range source IP")
	assert.False(t, IPInCIDRs("0.0.0.0", corrupted),
		"sentinel must deny the wildcard address")

	// patRestrictionFrom must produce a non-nil restriction for a corrupted column
	// (so the CIDR check fires and denies), not nil (which would skip the check).
	r := patRestrictionFrom(&models.PersonalAccessToken{AllowedCIDRs: `{bad}`})
	if assert.NotNil(t, r, "corrupted CIDR column must yield a non-nil restriction") {
		assert.Equal(t, patCIDRCorrupted, r.AllowedCIDRs)
	}
}
