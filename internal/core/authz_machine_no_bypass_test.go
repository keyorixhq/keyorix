package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMachineIdentity_NoAdminBypass_RealDB pins ADR-030's core containment property
// against the REAL role resolution (not mocks): a machine identity NEVER gets the
// admin-role short-circuit, even holding an admin-named role. A leaked machine token
// must be bounded by the role's explicit permissions, not silently elevated.
//
// The discriminator: `system.write` is NOT one of the admin role's explicit
// permissions (only super_admin has it). So a USER with the admin role is granted it
// only via the admin-role BYPASS, while a MACHINE with the SAME role — which goes
// straight to the permission check — must be denied.
func TestMachineIdentity_NoAdminBypass_RealDB(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityRole{}))

	// A user and a machine, each holding the SAME admin role at project 1.
	u := h.CreateTestUser(t, "adminuser", 400)
	h.AssignUserRole(t, u.ID, roleAdmin, ptr(1))
	require.NoError(t, h.DB.Create(&models.MachineIdentity{ID: 80, ProjectID: 1, Name: "ci", State: "active"}).Error)
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{MachineIdentityID: 80, RoleID: roleAdmin, ProjectID: 1}).Error)

	ctx := context.Background()
	scope := core.Scope{ProjectID: 1}

	// system.write is granted to the user ONLY through the admin-role bypass.
	userOK, err := h.CoreService.Authorize(ctx, u.ID, "system.write", scope)
	require.NoError(t, err)
	assert.True(t, userOK, "a user with the admin role bypasses to any permission")

	machineOK, err := h.CoreService.AuthorizePrincipal(ctx, core.ActorTypeMachine, 80, "system.write", scope)
	require.NoError(t, err)
	assert.False(t, machineOK, "a machine with the SAME admin role gets NO bypass — denied a permission the role lacks")

	// Sanity: the machine IS allowed permissions the admin role explicitly grants, so
	// the denial above is the bypass being withheld, not the machine path failing wholesale.
	machineRead, err := h.CoreService.AuthorizePrincipal(ctx, core.ActorTypeMachine, 80, "secrets.read", scope)
	require.NoError(t, err)
	assert.True(t, machineRead, "the machine still gets permissions the admin role explicitly grants")
}
