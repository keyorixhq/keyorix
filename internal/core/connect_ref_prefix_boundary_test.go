package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefMatches_SegmentBoundaryEnforced verifies that refMatches enforces a
// path-segment boundary for bare (non-glob) RefPrefix values: a grant with
// RefPrefix="db/prod" must NOT authorize reads of "db/production-adversary/creds"
// — a sibling namespace that a bare strings.HasPrefix would incorrectly allow.
// The fix replaces strings.HasPrefix with connect.RefWithinPrefix, which requires
// ref to equal the prefix exactly or extend it starting with '/'.
func TestRefMatches_SegmentBoundaryEnforced(t *testing.T) {
	// Exact match is always permitted.
	assert.True(t, refMatches("db/prod", "db/prod"),
		"exact match on the prefix itself is allowed")

	// Ref that extends the prefix on a proper segment boundary is permitted.
	assert.True(t, refMatches("db/prod", "db/prod/creds"),
		"ref extending prefix with '/' separator is allowed")
	assert.True(t, refMatches("db/prod", "db/prod/sub/nested"),
		"ref extending prefix on nested segment boundary is allowed")

	// Sibling namespace sharing prefix characters is DENIED (was wrong before fix).
	assert.False(t, refMatches("db/prod", "db/production-adversary/creds"),
		"sibling namespace 'db/production-adversary/creds' must NOT match prefix 'db/prod'")
	assert.False(t, refMatches("db/prod", "db/production"),
		"sibling path 'db/production' must NOT match prefix 'db/prod'")
	assert.False(t, refMatches("db/prod", "db/prodX/secret"),
		"sibling path 'db/prodX/secret' must NOT match prefix 'db/prod'")

	// Trailing-slash prefix scopes to the segment — the safe canonical form.
	assert.True(t, refMatches("db/prod/", "db/prod/creds"),
		"trailing-slash prefix matches within the namespace")
	assert.False(t, refMatches("db/prod/", "db/production/creds"),
		"trailing-slash prefix does NOT match the sibling namespace 'db/production/'")

	// Empty prefix is a connector-wide grant — matches everything.
	assert.True(t, refMatches("", "db/prod/creds"),
		"empty prefix is a connector-wide grant that matches any ref")
	assert.True(t, refMatches("", "anything"),
		"empty prefix matches any ref")
}

// TestConnectRefRBAC_SegmentBoundaryEnforced shows the same edge through the real
// enforcement path: a grant written with a bare prefix must NOT authorize a sibling
// namespace, whereas it must still authorize refs that are exactly the prefix or
// extend it on a segment boundary.
func TestConnectRefRBAC_SegmentBoundaryEnforced(t *testing.T) {
	ctx := context.Background()

	t.Run("bare prefix does not leak into the sibling namespace", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		seedRoleForUser(t, db, 1, 5, "prod-reader")
		seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045/#326 boundary matching, not the platform gate
		seedGrant(t, c, 5, "aws", "prod")          // bare prefix — NO trailing slash

		val, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "prod/db")
		require.NoError(t, err)
		assert.Equal(t, "v", val, "the intended namespace is allowed")

		_, err = c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "production/db")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted",
			"sibling namespace 'production/db' must be denied by a bare-prefix grant 'prod'")
	})

	t.Run("trailing-slash prefix confines the grant", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		seedRoleForUser(t, db, 1, 5, "prod-reader")
		seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045/#326 boundary matching, not the platform gate
		seedGrant(t, c, 5, "aws", "prod/")         // safe form — trailing slash

		val, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "prod/db")
		require.NoError(t, err)
		assert.Equal(t, "v", val, "the intended namespace is allowed")

		_, err = c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "production/db")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted",
			"the trailing-slash grant denies the sibling namespace 'production/'")
	})

	t.Run("exact ref match on the bare prefix is permitted", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		seedRoleForUser(t, db, 1, 5, "prod-reader")
		seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045/#326 boundary matching, not the platform gate
		seedGrant(t, c, 5, "aws", "prod/db")       // exact ref as prefix

		val, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "prod/db")
		require.NoError(t, err)
		assert.Equal(t, "v", val, "exact match on the prefix ref is allowed")
	})
}
