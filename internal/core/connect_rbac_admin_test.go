package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectRefRBAC_NoAdminBypass pins a deliberate asymmetry: the connect per-reference
// RBAC (ADR-045) has NO admin bypass, unlike core RBAC where an admin role short-circuits
// every permission check (Authorize → roleSetContainsAdmin). connectRefAllowed resolves
// only role-set membership against the grants, so once a connector is ref-scoped even a
// global super_admin is bounded by the grants — federated reads are deny-by-default for
// any role without a matching grant. This matters because a leaked or over-broad admin
// must not silently widen which external secrets can be pulled through a connector, and it
// is easy to regress by "helpfully" adding an admin shortcut to the federated-read path.
func TestConnectRefRBAC_NoAdminBypass(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})

	// User 1 is a GLOBAL super_admin — the role that bypasses core RBAC.
	seedRoleForUser(t, db, 1, 1, "super_admin")
	// The connector is ref-scoped, but only for a DIFFERENT role (reader = role 2).
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "reader"}).Error)
	seedGrant(t, c, 2, "aws", "metrics/")

	ctx := context.Background()

	// Precondition: the super_admin DOES bypass core RBAC — no connect.read permission is
	// seeded, yet Authorize returns true via the admin-name bypass.
	ok, err := c.Authorize(ctx, 1, "connect.read", Scope{})
	require.NoError(t, err)
	require.True(t, ok, "precondition: super_admin bypasses core RBAC")

	// But the per-reference policy still denies the admin: their role holds no matching
	// connect ref-grant on this scoped connector.
	_, err = c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "metrics/qps")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted", "the connect per-ref policy must not honor an admin bypass")

	// And it is an ordinary-role policy, not a hard block on admins: granting the admin
	// role itself a matching prefix lets the read through — proving the earlier denial was
	// policy-driven, not a special-case rejection of admins.
	seedGrant(t, c, 1, "aws", "metrics/")
	val, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "metrics/qps")
	require.NoError(t, err)
	assert.Equal(t, "v", val, "an explicit grant on the admin role authorizes the read")
}
