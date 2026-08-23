// groups_domain_allowlist_test.go — findings-core/core-project-members.json#5
// (PM-006): AddUserToGroup did not enforce the install's membership domain
// allowlist (SetMembershipDomainAllowlist / domainAllowedForUser,
// membership_lifecycle.go), even though a group membership confers every role
// the group holds at the matching scope — identical in effect to a direct
// AddProjectMember/InviteMember grant. That let an attacker with
// group-management rights bypass a "only @company.com may be onboarded into
// projects" allowlist entirely by routing the same access grant through group
// membership instead of a direct role/invite. Fixed by
// domainAllowedForGroupJoin (groups.go), called unconditionally from
// AddUserToGroup before the membership row is written.
package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestUserWithEmail creates a user with an explicit email, unlike
// h.CreateTestUser which always mints "<username>@test.com" — these tests need
// to control the domain to exercise the allowlist.
func createTestUserWithEmail(t *testing.T, h *testhelper.RBACTestHelper, username, email string, userID uint) *models.User {
	t.Helper()
	user := &models.User{ID: userID, Username: username, Email: email}
	require.NoError(t, h.DB.Create(user).Error)
	return user
}

// TestAddUserToGroup_RejectsDisallowedDomain_ProjectScopedGrant is the core
// regression: a group holding a role grant scoped to the SAME project as the
// membership confers project access exactly like AddProjectMember, so a
// disallowed-domain user must be refused, matching
// TestAddProjectMember_RejectsDisallowedDomain's assertions for the direct path.
func TestAddUserToGroup_RejectsDisallowedDomain_ProjectScopedGrant(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	const proj = uint(7)
	h.CreateTestRole(t, "domain_gate_role", "", 80)
	h.CreateTestGroup(t, "eng-project-group", "", 60)
	projID := proj
	h.AssignGroupRole(t, 60, 80, &projID) // project-scoped grant at proj 7

	mallory := createTestUserWithEmail(t, h, "mallory", "mallory@evil.com", 90)

	h.CoreService.SetMembershipDomainAllowlist([]string{"allowed.com"})

	// actorID 99 is arbitrary/unprivileged: domain_gate_role is not an
	// admin-tier role name, so requireAuthorityForRole imposes no ceiling here
	// — only the domain-allowlist gate under test is exercised.
	err := h.CoreService.AddUserToGroup(ctx, 99, false, mallory.ID, 60, proj)
	require.Error(t, err, "adding a disallowed-domain user to a group that confers project access must be refused")
	assert.Contains(t, err.Error(), "not on the allowlist")

	groups, gerr := h.Storage.GetUserGroups(ctx, mallory.ID)
	require.NoError(t, gerr)
	assert.Empty(t, groups, "the blocked membership must not have been persisted")
}

// TestAddUserToGroup_RejectsDisallowedDomain_GlobalMembershipReachesProjectGrant
// covers the case the naive "gate only when projectID != 0" fix would have
// missed: a GLOBAL membership (projectID == 0) still reaches every
// project-scoped grant the group holds (each at its own matching project, per
// GetUserGroupRoleIDsAt's scope semantics) — so it must be gated too, and is
// if anything the MORE dangerous route since it reaches every project the
// group has a grant in, not just one.
func TestAddUserToGroup_RejectsDisallowedDomain_GlobalMembershipReachesProjectGrant(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	const proj = uint(7)
	h.CreateTestRole(t, "domain_gate_role_2", "", 81)
	h.CreateTestGroup(t, "eng-project-group-2", "", 61)
	projID := proj
	h.AssignGroupRole(t, 61, 81, &projID) // project-scoped grant, group joined globally below

	trent := createTestUserWithEmail(t, h, "trent", "trent@evil.com", 91)

	h.CoreService.SetMembershipDomainAllowlist([]string{"allowed.com"})

	// projectID 0 == a GLOBAL membership, not a project-scoped one.
	err := h.CoreService.AddUserToGroup(ctx, 99, false, trent.ID, 61, 0)
	require.Error(t, err, "a global group join that reaches a project-scoped grant must still be refused")
	assert.Contains(t, err.Error(), "not on the allowlist")
}

// TestAddUserToGroup_AllowsAllowedDomain is the negative control: an
// allowed-domain user can still be added to a group that confers project
// access normally once the allowlist passes.
func TestAddUserToGroup_AllowsAllowedDomain(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	const proj = uint(7)
	h.CreateTestRole(t, "domain_gate_role_3", "", 82)
	h.CreateTestGroup(t, "eng-project-group-3", "", 62)
	projID := proj
	h.AssignGroupRole(t, 62, 82, &projID)

	peggy := createTestUserWithEmail(t, h, "peggy", "peggy@allowed.com", 92)

	h.CoreService.SetMembershipDomainAllowlist([]string{"allowed.com"})

	err := h.CoreService.AddUserToGroup(ctx, 99, false, peggy.ID, 62, proj)
	require.NoError(t, err, "an allowed-domain user must still be able to join a project-conferring group")

	groups, gerr := h.Storage.GetUserGroups(ctx, peggy.ID)
	require.NoError(t, gerr)
	var found bool
	for _, g := range groups {
		if g.ID == 62 {
			found = true
		}
	}
	assert.True(t, found, "the allowed membership must have been persisted")
}

// TestAddUserToGroup_NoRoleGrant_NotGatedByDomainAllowlist verifies the fix is
// scoped correctly: a group holding NO role grants at all confers no access,
// so joining it is not an onboarding path and must not be gated by the
// allowlist — mirroring the direct-grant paths, which only ever fire once a
// role is actually being assigned.
func TestAddUserToGroup_NoRoleGrant_NotGatedByDomainAllowlist(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestGroup(t, "org-chart-only-group", "", 63)
	oscar := createTestUserWithEmail(t, h, "oscar", "oscar@evil.com", 93)

	h.CoreService.SetMembershipDomainAllowlist([]string{"allowed.com"})

	err := h.CoreService.AddUserToGroup(ctx, 99, false, oscar.ID, 63, 0)
	require.NoError(t, err, "joining a group with no role grants confers no access and must not be gated")
}
