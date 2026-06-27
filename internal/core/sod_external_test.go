package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DetectSoDViolations flags a user whose effective permissions include both sides
// of a policy, and leaves a user holding only one side alone.
func TestDetectSoDViolations(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))

	ctx := context.Background()
	// editor (role 3) grants secrets.write + users.read; viewer (role 4) grants
	// secrets.read + users.read (no secrets.write).
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, nil) // editor (global) → holds both
	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 11, 4, nil) // viewer → only users.read

	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-useradmin", "", "secrets.write", "users.read")
	require.NoError(t, err)

	violations, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)

	var users []string
	for _, v := range violations {
		users = append(users, v.Username)
		assert.Equal(t, "write-vs-useradmin", v.PolicyName)
	}
	assert.Contains(t, users, "alice", "alice (editor) holds both secrets.write and users.read")
	assert.NotContains(t, users, "bob", "bob (viewer) lacks secrets.write")
}

// A toxic combination assembled across a DIRECT role and a GROUP-inherited role is
// still a violation — the detector must union both, exactly as Authorize does. Before
// the fix it consulted only direct user_roles, so a conflict satisfied via a group
// grant went silently undetected.
func TestDetectSoDViolations_GroupInheritedPermission(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	// carol holds secrets.read DIRECTLY (viewer, role 4) and secrets.write only via a
	// group carrying editor (role 3). Neither alone violates; together they do.
	h.CreateTestUser(t, "carol", 12)
	h.AssignUserRole(t, 12, 4, nil) // viewer (direct) → secrets.read
	h.CreateTestGroup(t, "writers", "secrets writers", 30)
	h.AssignGroupRole(t, 30, 3, nil) // group carries editor → secrets.write
	h.AssignUserToGroup(t, 12, 30)

	// dave holds only the direct viewer role — the negative control.
	h.CreateTestUser(t, "dave", 13)
	h.AssignUserRole(t, 13, 4, nil)

	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	violations, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)

	var users []string
	for _, v := range violations {
		users = append(users, v.Username)
	}
	assert.Contains(t, users, "carol", "carol holds secrets.write via her group and secrets.read directly")
	assert.NotContains(t, users, "dave", "dave holds only secrets.read")
}

// A user holding an admin permission-bypass role effectively holds BOTH sides of
// every policy — Authorize short-circuits on the admin role before consulting
// role_permissions, so the SoD scan must flag the admin even when their explicit
// role_permissions name only one side (or neither). Before the fix this most-
// privileged principal was invisible to the control.
func TestDetectSoDViolations_AdminBypass(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	// erin holds the admin role (role 2) — a permission-bypass role.
	h.CreateTestUser(t, "erin", 14)
	h.AssignUserRole(t, 14, 2, nil)
	// frank is a plain viewer (role 4) — holds neither side, the negative control.
	h.CreateTestUser(t, "frank", 15)
	h.AssignUserRole(t, 15, 4, nil)

	// A policy over two permissions the admin role does NOT explicitly enumerate.
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "approve-vs-admin", "", "access_requests.approve", "system.write")
	require.NoError(t, err)

	violations, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)

	var erinV *struct {
		detail   string
		username string
	}
	for _, v := range violations {
		if v.Username == "erin" {
			erinV = &struct {
				detail   string
				username string
			}{v.Detail, v.Username}
			assert.Equal(t, "user", v.PrincipalType)
		}
		assert.NotEqual(t, "frank", v.Username, "a plain viewer must not be flagged")
	}
	require.NotNil(t, erinV, "the admin must be flagged for the policy via bypass")
	assert.Contains(t, erinV.detail, "admin role")
}

// Machine identities hold roles and are authorized too, so a machine that holds both
// sides of a policy via its roles is a real violation. Before the fix the scan only
// iterated human users and never examined automation principals.
func TestDetectSoDViolations_MachinePrincipal(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{}))
	ctx := context.Background()

	// A CI machine that holds editor (role 3 → secrets.write) AND auditor (role 5 →
	// audit.read), a toxic write+audit combination.
	require.NoError(t, h.DB.Create(&models.MachineIdentity{ID: 70, Name: "ci-bot", State: "active", ProjectID: 1}).Error)
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{MachineIdentityID: 70, RoleID: 3}).Error)
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{MachineIdentityID: 70, RoleID: 5}).Error)
	// A suspended machine with the same grants must be ignored.
	require.NoError(t, h.DB.Create(&models.MachineIdentity{ID: 71, Name: "old-bot", State: "suspended", ProjectID: 1}).Error)
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{MachineIdentityID: 71, RoleID: 3}).Error)
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{MachineIdentityID: 71, RoleID: 5}).Error)

	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-audit", "", "secrets.write", "audit.read")
	require.NoError(t, err)

	violations, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)

	var found bool
	for _, v := range violations {
		if v.PrincipalType == "machine" && v.Username == "ci-bot" {
			found = true
			assert.Equal(t, uint(70), v.UserID)
		}
		assert.NotEqual(t, "old-bot", v.Username, "a suspended machine must not be flagged")
	}
	assert.True(t, found, "the active CI machine holding both sides must be flagged")
}

// With no policies, there are no violations.
func TestDetectSoDViolations_NoPolicies(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}))
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, nil)

	v, err := h.CoreService.DetectSoDViolations(context.Background())
	require.NoError(t, err)
	assert.Empty(t, v)
}

// CreateSoDPolicy validates its inputs.
func TestCreateSoDPolicy_Validation(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "", "", "a", "b")
	require.Error(t, err, "name required")
	_, err = h.CoreService.CreateSoDPolicy(ctx, 1, "n", "", "secrets.read", "secrets.read")
	require.Error(t, err, "the two permissions must differ")
	_, err = h.CoreService.CreateSoDPolicy(ctx, 1, "n", "", "secrets.read", "")
	require.Error(t, err, "both permissions required")

	// A valid policy is listed and deletable.
	p, err := h.CoreService.CreateSoDPolicy(ctx, 1, "ok", "d", "roles.assign", "secrets.delete")
	require.NoError(t, err)
	list, err := h.CoreService.ListSoDPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.NoError(t, h.CoreService.DeleteSoDPolicy(ctx, 1, p.ID))
	require.Error(t, h.CoreService.DeleteSoDPolicy(ctx, 1, p.ID), "already deleted")
}
