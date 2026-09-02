// users_atomic_ceiling_test.go — #480: CreateUserWithAssignments is InviteGlobal's
// sibling (both mint a system role plus a set of project assignments in one call),
// and needed the identical escalation-by-proxy ceiling. FIX-1 rerouted this ceiling
// from requireAuthorityForRole (name-based: only fired for the 4 canonical
// admin-tier role names) to requireGranterHoldsRolePermissions (derives the ceiling
// from the role's real bundled permissions) -- the error text below changed to
// match ("cannot grant this role: you do not hold permission ... yourself").
// These tests mirror TestInviteGlobal_RejectsNonAdminGranting* (#231) exactly.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #480: CreateUserWithAssignments must refuse a non-admin actor granting a global
// admin system role — mirrors TestInviteGlobal_RejectsNonAdminGrantingGlobalAdminRole.
func TestCreateUserWithAssignments_RejectsNonAdminGrantingGlobalAdminRole(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	// A non-admin actor holding only project_developer (no admin-tier role anywhere,
	// but plausibly also holding roles.assign via a custom role in the real HTTP/gRPC
	// deployment) must not be able to mint an admin account in one call.
	nonAdminID := seedUserWithRole(t, st, "cua-attacker", "project_developer", storage.Scope{})

	_, err := c.CreateUserWithAssignments(ctx, &CreateUserRequest{
		Username: "cua-mallory", Email: "cua-mallory@acme.io", Password: "Qr7#Kp2$Lm5@Vn9!",
	}, "admin", nil, nonAdminID, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not hold permission")
}

// #480: the per-project assignments bundled into an atomic create must be
// individually ceiling-checked too — mirrors
// TestInviteGlobal_RejectsNonAdminGrantingProjectAdminAssignment.
func TestCreateUserWithAssignments_RejectsNonAdminGrantingProjectAdminAssignment(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	nonAdminID := seedUserWithRole(t, st, "cua-attacker-2", "project_developer", storage.Scope{})
	proj, err := st.CreateProject(ctx, &models.Project{Name: "cua-target-project"})
	require.NoError(t, err)

	_, err = c.CreateUserWithAssignments(ctx, &CreateUserRequest{
		Username: "cua-mallory-2", Email: "cua-mallory-2@acme.io", Password: "Qr7#Kp2$Lm5@Vn9!",
	}, "system_viewer", []ProjectAssignment{
		{ProjectID: proj.ID, Role: "project_admin"},
	}, nonAdminID, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not hold permission")
}

// #480 positive control: a genuinely admin actor can still mint an account with a
// system role and project assignments in one call — no regression for the
// legitimate case.
func TestCreateUserWithAssignments_AdminActorAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	admin := seedUserWithRole(t, st, "cua-admin", "admin", storage.Scope{})
	proj, err := st.CreateProject(ctx, &models.Project{Name: "cua-legit-project"})
	require.NoError(t, err)

	created, err := c.CreateUserWithAssignments(ctx, &CreateUserRequest{
		Username: "cua-newbie", Email: "cua-newbie@acme.io", Password: "Qr7#Kp2$Lm5@Vn9!",
	}, "system_admin", []ProjectAssignment{
		{ProjectID: proj.ID, Role: "project_admin"},
	}, admin, false)
	require.NoError(t, err)
	assert.Equal(t, "cua-newbie", created.Username)
}

// #480 positive control: a non-admin actor CAN still atomically create a user with
// roles the actor already holds every bundled permission of — the ceiling
// (requireGranterHoldsRolePermissions) only bites when the grant would exceed the
// actor's own standing, so the common onboarding case (a manager provisioning a
// teammate with access no broader than their own) is unaffected. The actor is
// seeded with BOTH project_developer (for the project assignment) and system_viewer
// (for the global system-role grant) — under FIX-1's real permission-derived
// ceiling, unlike the old name-based one, the actor must actually hold whatever
// they're granting, even for a "non-admin-tier" role name.
func TestCreateUserWithAssignments_NonAdminRoleAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	// project_developer is scoped to project 1 specifically — the ceiling checks
	// the actor's OWN holdings at the SAME scope as the grant, so the project
	// assignment below must target project 1 too, not a freshly created project
	// the actor holds nothing on.
	actor := seedUserWithRole(t, st, "cua-actor", "project_developer", storage.Scope{ProjectID: 1})
	viewerRole, err := st.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, actor, viewerRole.ID, storage.Scope{}))

	created, err := c.CreateUserWithAssignments(ctx, &CreateUserRequest{
		Username: "cua-teammate", Email: "cua-teammate@acme.io", Password: "Qr7#Kp2$Lm5@Vn9!",
	}, "system_viewer", []ProjectAssignment{
		{ProjectID: 1, Role: "project_developer"},
	}, actor, false)
	require.NoError(t, err)
	assert.Equal(t, "cua-teammate", created.Username)
}
