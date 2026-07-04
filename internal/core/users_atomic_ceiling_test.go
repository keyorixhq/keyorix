// users_atomic_ceiling_test.go — #480: CreateUserWithAssignments is InviteGlobal's
// sibling (both mint a system role plus a set of project assignments in one call),
// and needed the identical escalation-by-proxy ceiling (requireAuthorityForRole).
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
	}, "admin", nil, nonAdminID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only an administrator can grant")
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
	}, nonAdminID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only an administrator can grant")
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
	}, admin)
	require.NoError(t, err)
	assert.Equal(t, "cua-newbie", created.Username)
}

// #480 positive control: a non-admin actor CAN still atomically create a user with
// a non-admin-tier system role and non-admin-tier project assignments — the ceiling
// only bites on admin-tier grants (isAdminRoleName), so the common onboarding case
// (e.g. a project_developer-holding manager provisioning another developer) is
// unaffected.
func TestCreateUserWithAssignments_NonAdminRoleAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	actor := seedUserWithRole(t, st, "cua-actor", "project_developer", storage.Scope{ProjectID: 1})
	proj, err := st.CreateProject(ctx, &models.Project{Name: "cua-nonadmin-project"})
	require.NoError(t, err)

	created, err := c.CreateUserWithAssignments(ctx, &CreateUserRequest{
		Username: "cua-teammate", Email: "cua-teammate@acme.io", Password: "Qr7#Kp2$Lm5@Vn9!",
	}, "system_viewer", []ProjectAssignment{
		{ProjectID: proj.ID, Role: "project_developer"},
	}, actor)
	require.NoError(t, err)
	assert.Equal(t, "cua-teammate", created.Username)
}
