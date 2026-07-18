// testhelper_s36_test.go — exercises every public and private function in
// rbac_test_helper.go to bring package coverage from 0% to ~100%.
package testhelper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRBACTestHelper_S36(t *testing.T) {
	h := NewRBACTestHelper(t)
	require.NotNil(t, h)
	require.NotNil(t, h.CoreService)
	require.NotNil(t, h.DB)
	require.NotNil(t, h.SqlDB)
	require.NotNil(t, h.Storage)

	// CreateTestUser
	user := h.CreateTestUser(t, "alice", 100)
	require.NotNil(t, user)
	assert.Equal(t, uint(100), user.ID)
	assert.Equal(t, "alice", user.Username)

	// CreateTestRole
	role := h.CreateTestRole(t, "custom_role", "Custom test role", 50)
	require.NotNil(t, role)
	assert.Equal(t, uint(50), role.ID)
	assert.Equal(t, "custom_role", role.Name)

	// CreateTestGroup
	group := h.CreateTestGroup(t, "test_group", "A test group", 10)
	require.NotNil(t, group)
	assert.Equal(t, uint(10), group.ID)
	assert.Equal(t, "test_group", group.Name)

	// AssignUserRole — nil project (global scope → derefScope nil path)
	h.AssignUserRole(t, user.ID, role.ID, nil)

	// AssignUserRole — non-nil project (derefScope non-nil path)
	projectID := uint(1)
	h.AssignUserRole(t, user.ID, 1, &projectID)

	// AssignUserToGroup
	h.AssignUserToGroup(t, user.ID, group.ID)

	// AssignGroupRole — nil project
	h.AssignGroupRole(t, group.ID, role.ID, nil)

	// AssignGroupRole — non-nil project
	h.AssignGroupRole(t, group.ID, 1, &projectID)

	// CreateTestSecret
	secret := h.CreateTestSecret(t, "my-secret", user.ID, 200)
	require.NotNil(t, secret)
	assert.Equal(t, uint(200), secret.ID)
	assert.Equal(t, "my-secret", secret.Name)

	// GetUserRoles
	roles := h.GetUserRoles(t, user.ID)
	assert.NotEmpty(t, roles)

	// GetUserPermissions
	perms := h.GetUserPermissions(t, user.ID)
	assert.NotNil(t, perms)

	// HasPermission
	_ = h.HasPermission(t, user.ID, "roles.read")

	// CreateTestContext
	ctx := h.CreateTestContext(user.ID, user.Username)
	require.NotNil(t, ctx)
	assert.Equal(t, user.ID, ctx.Value(testContextKeyUserID))
	assert.Equal(t, user.Username, ctx.Value(testContextKeyUsername))

	// derefScope — nil branch (covered via AssignUserRole nil above)
	// derefScope — non-nil branch (covered via AssignUserRole &projectID above)
	// Explicitly test both paths of derefScope
	assert.Equal(t, uint(0), derefScope(nil))
	assert.Equal(t, uint(7), derefScope(func() *uint { v := uint(7); return &v }()))
}
