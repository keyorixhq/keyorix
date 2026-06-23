package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefMatches_BarePrefixIsNotASegmentBoundary pins the documented prefix semantics of a
// ConnectRefGrant whose RefPrefix has no glob metacharacters (ADR-045): it is matched with
// strings.HasPrefix — a substring prefix, NOT a path-segment boundary. So a bare prefix
// "prod" also authorizes the SIBLING namespace "production/...". The safe, segment-scoped
// form is the trailing slash, "prod/". This is a real operator footgun (an unintentionally
// over-broad grant), the same class of start-only prefix bug as the rotation-ref URL
// injection note — so pin both the sharp edge and the safe pattern, and force any change to
// the matching semantics to be a deliberate, reviewed decision.
func TestRefMatches_BarePrefixIsNotASegmentBoundary(t *testing.T) {
	// A bare prefix matches its own namespace — and also leaks into a sibling one.
	assert.True(t, refMatches("prod", "prod/db"), "bare prefix matches within its own namespace")
	assert.True(t, refMatches("prod", "production/db"),
		"FOOTGUN: a bare prefix also matches the sibling namespace 'production/' (HasPrefix, not a path boundary)")

	// A trailing slash scopes the grant to the segment — the safe form.
	assert.True(t, refMatches("prod/", "prod/db"), "trailing-slash prefix matches within the namespace")
	assert.False(t, refMatches("prod/", "production/db"),
		"a trailing-slash prefix does NOT leak into the sibling namespace 'production/'")
}

// TestConnectRefRBAC_BarePrefixOverMatchesSiblingNamespace shows the same edge through the
// real enforcement path: a grant written with a bare prefix authorizes a sibling namespace
// the operator likely did not intend, whereas the trailing-slash grant confines the read.
// Pinning the end-to-end behavior keeps the footgun visible and the fix (write prefixes
// with a trailing slash) discoverable.
func TestConnectRefRBAC_BarePrefixOverMatchesSiblingNamespace(t *testing.T) {
	ctx := context.Background()

	t.Run("bare prefix leaks into the sibling namespace", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		seedRoleForUser(t, db, 1, 5, "prod-reader")
		seedGrant(t, c, 5, "aws", "prod") // bare prefix — NO trailing slash

		val, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "prod/db")
		require.NoError(t, err)
		assert.Equal(t, "v", val, "the intended namespace is allowed")

		val, err = c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "production/db")
		require.NoError(t, err)
		assert.Equal(t, "v", val,
			"FOOTGUN: the bare-prefix grant also authorizes the sibling namespace 'production/'")
	})

	t.Run("trailing-slash prefix confines the grant", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		seedRoleForUser(t, db, 1, 5, "prod-reader")
		seedGrant(t, c, 5, "aws", "prod/") // safe form — trailing slash

		val, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "prod/db")
		require.NoError(t, err)
		assert.Equal(t, "v", val, "the intended namespace is allowed")

		_, err = c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "production/db")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted",
			"the trailing-slash grant denies the sibling namespace 'production/'")
	})
}
