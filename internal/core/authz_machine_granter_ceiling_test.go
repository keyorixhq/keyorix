package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PART2-CONT-6 (Part 2 regression audit, second attempt): requireGranterHoldsRolePermissions
// must resolve a machine-authenticated granter's REAL permission set for a
// genuine DIRECT (non-proxy) request, without reopening the fail-open node-
// credential escalation the first attempt introduced. WithSelfMachineGranter
// is a narrowly-scoped tag ONLY direct HTTP/gRPC handlers set (never a
// /system proxy relay) -- these tests exercise it directly, mirroring how
// server/http/handlers/machine_identities.go's changeMachineRole (and its
// siblings) now tag ctx before calling into core.
func TestAssignMachineRole_MachineGranterHoldingRolePermissionsAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	granter, err := c.CreateMachineIdentity(ctx, 1, "granter", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateMachineIdentity(ctx, 1, "target", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	devRole, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	// Seed the granter's own permissions directly at the storage layer,
	// bypassing the ceiling check itself (the same pattern
	// TestAddUserToGroup_EscalationByProxyBlocked uses for its group's grant).
	require.NoError(t, st.AssignMachineRole(ctx, granter.ID, devRole.ID, storage.Scope{ProjectID: 1}))

	// Tag ctx exactly as a real direct (non-proxy) HTTP/gRPC handler does --
	// WithSelfMachineGranter, NOT the general-purpose WithMachineActor a
	// /system proxy relay's request would also carry.
	grantCtx := WithSelfMachineGranter(ctx, granter.ID)

	err = c.AssignMachineRole(grantCtx, target.ID, devRole.ID, Scope{ProjectID: 1}, 0, true)
	require.NoError(t, err, "a machine granter that already holds every permission the role bundles must be allowed to grant that same role")
}

// Non-regression counterpart: a machine granter that does NOT hold the
// target role's full permission set must still be refused -- proving the fix
// resolves the machine's REAL permissions rather than failing open.
func TestAssignMachineRole_MachineGranterMissingRolePermissionsBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	granter, err := c.CreateMachineIdentity(ctx, 1, "granter2", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateMachineIdentity(ctx, 1, "target2", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, granter.ID, viewerRole.ID, storage.Scope{ProjectID: 1}))

	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)

	grantCtx := WithSelfMachineGranter(ctx, granter.ID)
	err = c.AssignMachineRole(grantCtx, target.ID, adminRole.ID, Scope{ProjectID: 1}, 0, true)
	require.Error(t, err, "a machine granter holding only project_viewer must not be able to grant project_admin")
	assert.Contains(t, err.Error(), "cannot grant this role")
}

// actorIsMachine set but ctx carries no WithSelfMachineGranter tag (e.g. a
// /system proxy relay, or any call path not updated to tag itself) must
// fail closed, exactly as it did before this fix -- never regress to a
// WORSE (fail-open) outcome just because the tag is absent. This is the
// exact shape the reverted first attempt got wrong when it consulted the
// general-purpose WithMachineActor tag instead.
func TestAssignMachineRole_MachineGranterUntaggedContextFailsClosed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	granter, err := c.CreateMachineIdentity(ctx, 1, "granter3", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateMachineIdentity(ctx, 1, "target3", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	devRole, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, granter.ID, devRole.ID, storage.Scope{ProjectID: 1}))

	// No WithSelfMachineGranter tag on ctx. Even tagging with the general
	// WithMachineActor (what a /system proxy relay's ctx legitimately carries
	// for audit purposes) must NOT be treated as authorization -- prove that
	// distinction holds, not just "no tag at all".
	untrustedCtx := WithMachineActor(ctx, granter.ID)
	err = c.AssignMachineRole(untrustedCtx, target.ID, devRole.ID, Scope{ProjectID: 1}, 0, true)
	require.Error(t, err, "actorIsMachine with only the general-purpose audit tag (no WithSelfMachineGranter) must fail closed")
	assert.Contains(t, err.Error(), "cannot grant this role")
}
