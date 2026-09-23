package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A /system proxy tags its machine caller with WithSystemProxyMachineGranter
// (PR #1979 CI fix): the relaying credential's own permissions clear the
// roles.assign baseline and non-admin grants, but an admin-tier role --
// canonical admin name, or a non-canonical bundle roleIsAdminTier classifies
// as administrative (#1685) -- must never be granted on the strength of a
// relay credential's authority, even one holding global admin like a node
// credential (server/http/integration_test.go's createNodeToken).
func TestSystemProxyRelayGranter_RefusesAdminTierRoles(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	node, err := c.CreateMachineIdentity(ctx, 1, "relay-node", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateMachineIdentity(ctx, 1, "relay-target", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	globalAdmin, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, node.ID, globalAdmin.ID, storage.Scope{}))

	// Non-canonical admin-tier role: bundles only roles.assign.
	name, err := identity.NewFoldedName("relay_test_role_assigner")
	require.NoError(t, err)
	customAdminTier, err := st.CreateRole(ctx, name, "test-only: roles.assign only")
	require.NoError(t, err)
	perms, err := st.ListPermissions(ctx)
	require.NoError(t, err)
	for _, p := range perms {
		if p.Name == "roles.assign" {
			require.NoError(t, st.AssignPermissionToRole(ctx, customAdminTier.ID, p.ID))
		}
	}
	projectAdmin, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)

	relayCtx := WithSystemProxyMachineGranter(ctx, node.ID)
	for _, role := range []struct {
		name string
		id   uint
	}{{"project_admin", projectAdmin.ID}, {"custom roles.assign-only", customAdminTier.ID}} {
		err := c.AssignMachineRole(relayCtx, target.ID, role.id, Scope{ProjectID: 1}, 0, true)
		require.Error(t, err, "a /system relay must not grant admin-tier role %s", role.name)
		assert.Contains(t, err.Error(), "/system relay")
	}

	require.NoError(t, c.AssignMachineRole(relayCtx, target.ID, viewer.ID, Scope{ProjectID: 1}, 0, true),
		"a non-admin-tier grant within the relay credential's own authority still relays")

	// The same admin-tier grant by the same machine acting AS ITSELF on a
	// direct (non-proxy) route is governed by its own permissions, as before.
	require.NoError(t, c.AssignMachineRole(WithSelfMachineGranter(ctx, node.ID), target.ID, customAdminTier.ID, Scope{ProjectID: 1}, 0, true))
}
