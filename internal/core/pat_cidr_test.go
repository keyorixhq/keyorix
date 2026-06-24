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
