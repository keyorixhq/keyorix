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

// A toxic pair held with one permission DIRECT and the other inherited via a GROUP is a
// real SoD violation and must be flagged — effective permissions include group-inherited
// roles, not just directly-assigned ones.
func TestDetectSoDViolations_GroupInheritedPermission(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	// carol holds users.read directly (viewer, role 4) and secrets.write ONLY via a group
	// (editor, role 3). Neither side alone is a violation; together they are.
	h.CreateTestUser(t, "carol", 12)
	h.AssignUserRole(t, 12, 4, nil) // viewer (direct) → users.read (+ secrets.read)
	h.CreateTestGroup(t, "writers", "", 5)
	h.AssignGroupRole(t, 5, 3, nil) // editor on the group → secrets.write
	h.AssignUserToGroup(t, 12, 5)   // carol joins → inherits secrets.write

	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-useradmin", "", "secrets.write", "users.read")
	require.NoError(t, err)

	violations, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)

	var users []string
	for _, v := range violations {
		users = append(users, v.Username)
	}
	assert.Contains(t, users, "carol",
		"carol holds users.read directly and secrets.write via a group — a group-inherited SoD violation")
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
