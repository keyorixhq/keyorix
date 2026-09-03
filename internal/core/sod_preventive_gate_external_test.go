package core_test

// sod_preventive_gate_external_test.go — #419: DetectSoDViolations (sod.go) is a
// purely periodic/on-demand DETECTIVE control; combined with JIT/time-bound role
// grants, a toxic-permission overlap that both starts and fully expires between two
// scans is exercisable through Authorize() but never appears in any report. These
// tests prove the grant-time PREVENTIVE gate (requireNoSoDViolation and friends,
// sod.go) closes that window: a grant that would newly complete an SoD policy is
// blocked at every direct role-grant choke point, a grant that does NOT is
// unaffected (non-regression), and break-glass's self-service emergency access is
// deliberately exempt (it is documented as un-gated by RBAC by design).

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// role/permission fixture reminder (testhelper.seedTestData): role 2 = admin
// (bypass), role 3 = editor (secrets.read, secrets.write, users.read), role 4 =
// viewer (secrets.read, users.read), role 5 = auditor (audit.read, audit.admin,
// system.read, users.read, roles.read).

// AssignUserRole must BLOCK a grant that would newly complete an SoD policy given
// the target user's OTHER current permissions — the direct-grant half of #419.
func TestAssignUserRole_BlocksNewSoDViolation(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 4, nil) // viewer (global) → secrets.read, users.read

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	// editor adds secrets.write — combined with alice's existing secrets.read this
	// newly completes the policy, so the grant must be refused. actorID 0 is the
	// system pseudo-actor (bypasses the unrelated grant-ceiling check — #93/#107/
	// #141 — so only the SoD gate under test is exercised).
	err = h.CoreService.AssignUserRole(ctx, 0, 10, 3, core.Scope{}, false)
	require.Error(t, err, "granting editor must be blocked: it would create a new SoD violation")
	assert.Contains(t, err.Error(), "separation-of-duties")

	ids, gerr := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{})
	require.NoError(t, gerr)
	assert.NotContains(t, ids, uint(3), "the blocked grant must not have been persisted")
}

// A grant that does NOT complete any SoD policy must still succeed normally —
// critical non-regression, since this gate now runs on every role-grant path.
func TestAssignUserRole_AllowsNonViolatingGrant(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 11, 4, nil) // viewer → secrets.read, users.read

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	// auditor (audit.read, audit.admin, system.read, users.read, roles.read) shares
	// no permission with either side of the policy beyond what bob already holds
	// alone — granting it completes nothing.
	err = h.CoreService.AssignUserRole(ctx, 0, 11, 5, core.Scope{}, false)
	require.NoError(t, err, "a non-violating grant must succeed unimpeded")

	ids, gerr := h.Storage.GetUserRoleIDsAt(ctx, 11, storage.Scope{})
	require.NoError(t, gerr)
	assert.Contains(t, ids, uint(5), "the auditor role must have been granted")
}

// AssignUserRoleWithExpiry (the JIT/time-bound grant path) must ALSO block a
// newly-completing SoD violation — this is the exact timing-evasion vector #419
// describes: without this, a toxic overlap granted with an expiry could start and
// fully expire between two DetectSoDViolations runs, invisible to the periodic
// scan, while still genuinely authorizing access for its whole (short) lifetime.
func TestAssignUserRoleWithExpiry_BlocksJITSoDViolation(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestUser(t, "carol", 12)
	h.AssignUserRole(t, 12, 4, nil) // viewer → secrets.read
	// #G15/#93/#107/#141: the granting actor must themselves hold every
	// permission of the role being granted — grant "admin" globally so the
	// ceiling check's admin bypass applies (this test targets the SoD gate
	// specifically, not the ceiling check).
	h.AssignUserRole(t, 1, 2, nil)

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	expiresAt := time.Now().Add(1 * time.Hour)
	err = h.CoreService.AssignUserRoleWithExpiry(ctx, 1, 12, 3, core.Scope{}, expiresAt, false)
	require.Error(t, err, "a short-lived JIT grant that would create a toxic overlap must be blocked too, closing the timing-evasion window")
	assert.Contains(t, err.Error(), "separation-of-duties")

	ids, gerr := h.Storage.GetUserRoleIDsAt(ctx, 12, storage.Scope{})
	require.NoError(t, gerr)
	assert.NotContains(t, ids, uint(3), "the blocked time-bound grant must not have been persisted")
}

// The JIT path's non-regression counterpart: a time-bound grant that does not
// complete any policy must still succeed and actually authorize.
func TestAssignUserRoleWithExpiry_AllowsNonViolatingGrant(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestUser(t, "dave", 13)
	h.AssignUserRole(t, 13, 4, nil) // viewer
	// #G15/#93/#107/#141: the granting actor must themselves hold every
	// permission of the role being granted — grant "admin" globally so the
	// ceiling check's admin bypass applies.
	h.AssignUserRole(t, 1, 2, nil)

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	expiresAt := time.Now().Add(1 * time.Hour)
	err = h.CoreService.AssignUserRoleWithExpiry(ctx, 1, 13, 5, core.Scope{}, expiresAt, false) // auditor
	require.NoError(t, err, "a non-violating time-bound grant must succeed unimpeded")

	ids, gerr := h.Storage.GetUserRoleIDsAt(ctx, 13, storage.Scope{})
	require.NoError(t, gerr)
	assert.Contains(t, ids, uint(5))
}

// Granting a role to a GROUP is inherited by every member exactly like a direct
// grant, so it must be checked the same way — a member who would newly complete a
// policy blocks the whole group-role assignment.
func TestAssignRoleToGroup_BlocksNewSoDViolationForMember(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestUser(t, "erin", 14)
	h.AssignUserRole(t, 14, 4, nil) // viewer directly → secrets.read
	h.CreateTestGroup(t, "writers", "", 30)
	h.AssignUserToGroup(t, 14, 30)

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	// Granting editor (secrets.write) to the GROUP would complete the policy for
	// erin, its member.
	err = h.CoreService.AssignRoleToGroup(ctx, 1, 30, 3, core.Scope{}, false)
	require.Error(t, err, "the group grant must be blocked on behalf of the member it would newly violate for")
	assert.Contains(t, err.Error(), "separation-of-duties")

	roles, gerr := h.CoreService.GetGroupRoles(ctx, 30)
	require.NoError(t, gerr)
	for _, r := range roles {
		assert.NotEqual(t, uint(3), r.ID, "the blocked group role must not have been persisted")
	}
}

// A group-role grant that violates nothing for any current member must still
// succeed normally.
func TestAssignRoleToGroup_AllowsNonViolatingGrant(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestUser(t, "frank", 15)
	h.AssignUserRole(t, 15, 4, nil) // viewer
	h.CreateTestGroup(t, "auditors", "", 31)
	h.AssignUserToGroup(t, 15, 31)

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	err = h.CoreService.AssignRoleToGroup(ctx, 1, 31, 5, core.Scope{}, false) // auditor: no conflict
	require.NoError(t, err, "a non-violating group grant must succeed unimpeded")

	roles, gerr := h.CoreService.GetGroupRoles(ctx, 31)
	require.NoError(t, gerr)
	var found bool
	for _, r := range roles {
		if r.ID == 5 {
			found = true
		}
	}
	assert.True(t, found, "the auditor role must have been granted to the group")
}

// CreateUserWithAssignments mints a BRAND-NEW user's roles atomically, so there is
// no existing user ID to check "other current grants" against — the preventive
// gate instead evaluates whether the FULL set of role grants landing together
// would complete a policy (requireGrantSetNoSoDViolation).
func TestCreateUserWithAssignments_BlocksNewSoDViolationAcrossGrantSet(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	// The global system role is "viewer" (secrets.read) and the lone project
	// assignment is "editor" (secrets.write) — together, in one atomic call, they
	// complete the policy for a user who a moment ago didn't exist at all. Project 1
	// ("default") is already seeded by testhelper.seedTestData.
	_, err = h.CoreService.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
		Username: "grace", Email: "grace@test.com", DisplayName: "Grace", Password: "Sup3rS3cret!Pass",
	}, "viewer", []core.ProjectAssignment{{ProjectID: 1, Role: "editor"}}, 0, false)
	require.Error(t, err, "the combined grant set must be refused for completing an SoD policy")
	assert.Contains(t, err.Error(), "separation-of-duties")

	_, gerr := h.CoreService.GetUserByEmail(ctx, "grace@test.com")
	assert.Error(t, gerr, "no user must have been created")
}

// A brand-new user's combined role grants that do NOT complete any policy must
// still succeed normally.
func TestCreateUserWithAssignments_AllowsNonViolatingGrantSet(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	// Project 1 ("default") is already seeded by testhelper.seedTestData.
	created, err := h.CoreService.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
		Username: "heidi", Email: "heidi@test.com", DisplayName: "Heidi", Password: "Sup3rS3cret!Pass",
	}, "viewer", []core.ProjectAssignment{{ProjectID: 1, Role: "auditor"}}, 0, false)
	require.NoError(t, err, "a non-violating grant set must succeed unimpeded")
	assert.NotZero(t, created.ID)
}

// Break-glass self-service emergency access must NOT be blocked by the #419
// preventive gate, even when the emergency role would (by the ordinary rule)
// newly complete an SoD policy — break-glass is documented as deliberately
// un-gated by RBAC (its whole point is access the user does not already have),
// and a false-positive SoD block during a genuine incident would be an
// unacceptable failure mode. See assignUserRoleWithExpirySkipSoD (jit_access.go).
func TestActivateBreakGlass_NotBlockedBySoD(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}, &models.BreakGlassActivation{}))
	ctx := context.Background()

	h.CoreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "editor", DefaultTTL: 4 * time.Hour, MaxTTL: 24 * time.Hour,
	})

	const proj = uint(2)
	h.CreateTestUser(t, "ivan", 16)
	pid := proj
	h.AssignUserRole(t, 16, 4, &pid) // viewer at the project → secrets.read

	// This policy would ordinarily block granting "editor" (secrets.write) to a
	// principal who already holds secrets.read.
	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	act, err := h.CoreService.ActivateBreakGlass(ctx, proj, 16, "prod incident requiring editor access", "")
	require.NoError(t, err, "break-glass must not be blocked by the SoD preventive gate")
	assert.Equal(t, core.BreakGlassActive, act.State)

	ids, gerr := h.Storage.GetUserRoleIDsAt(ctx, 16, storage.Scope{ProjectID: proj})
	require.NoError(t, gerr)
	assert.Contains(t, ids, uint(3), "the emergency role was actually granted despite the SoD policy")
}

// A principal who already holds an admin permission-bypass role is out of scope
// for the preventive gate (see sod.go's package doc): they trivially "violate"
// every policy already, and blocking further grants to them would refuse ALL
// admin-role-holder provisioning the moment any SoD policy exists.
func TestAssignUserRole_AdminBypassNotBlockedBySoD(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestUser(t, "judy", 17)
	h.AssignUserRole(t, 17, 2, nil) // admin (permission-bypass)

	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	err = h.CoreService.AssignUserRole(ctx, 0, 17, 3, core.Scope{}, false) // editor
	require.NoError(t, err, "granting a role to an existing admin-bypass holder must not be refused by the SoD gate")
}

// TestAssignUserRole_ProjectScopedAdminNotExemptFromSoD is the #G01
// regression: an admin role granted only at a specific project must NOT
// exempt the holder from the SoD preventive gate the way a true global admin
// is exempted — SoD policies are principal-level and scope-agnostic by
// design ("a user must never hold both sides ANYWHERE"), so a project-scoped
// admin's own bundled permissions can still combine with a new grant to
// complete a policy, and that must be blocked like any non-admin grant.
func TestAssignUserRole_ProjectScopedAdminNotExemptFromSoD(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.CreateTestUser(t, "kim", 18)
	// "admin" (role 2) bundles secrets.write but NOT audit.admin — grant it to
	// kim scoped ONLY to project 9, not globally.
	projectID := uint(9)
	h.AssignUserRole(t, 18, 2, &projectID)

	// Policy pairs secrets.write (already in kim's project-scoped admin bundle)
	// with audit.admin (only "auditor", role 5, bundles it).
	h.AssignUserRole(t, 1, 1, nil) // #1529: actor 1 must now be admin-tier to manage SoD policies
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-audit-admin", "", "secrets.write", "audit.admin")
	require.NoError(t, err)

	err = h.CoreService.AssignUserRole(ctx, 0, 18, 5, core.Scope{}, false) // auditor
	require.Error(t, err, "a project-scoped admin must still be blocked by the SoD gate, unlike a true global admin")
	assert.Contains(t, err.Error(), "separation-of-duties")
}
