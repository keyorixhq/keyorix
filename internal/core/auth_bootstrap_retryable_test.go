// auth_bootstrap_retryable_test.go — regression tests for a first-boot
// failure that left an install unable to bootstrap ever again (FINDINGS-inbox,
// Session J, 2026-09-28, reproduced on a kind cluster via the Helm quick-start).
//
// bootstrapSystemLocked seeded permissions and roles, THEN called CreateUser,
// whose personal-info password check ("must not contain your username, email,
// or display name") is stricter than the pre-check it ran first (which passed
// a nil user). A password like "Change-This-Admin-Pw1" for user "admin" passed
// the pre-check, was rejected by CreateUser AFTER the permission rows were
// committed, and every later /system/init — with any password — failed with a
// duplicate-key 500 on the first permission. Only wiping the DB recovered.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const retryToken = "retry-bootstrap-token"

// The password Session J actually used: 16+ chars with upper/lower/digit/special,
// but it contains the username "admin" (case-insensitively).
func personalInfoPasswordReq() *BootstrapRequest {
	return &BootstrapRequest{
		Username: "admin", Email: "admin@example.com",
		Password: "Change-This-Admin-Pw1", DisplayName: "Administrator", Token: retryToken,
	}
}

func goodRetryReq() *BootstrapRequest {
	return &BootstrapRequest{
		Username: "admin", Email: "admin@example.com",
		Password: "Kx7!Bootstrap-Pwd", DisplayName: "Administrator", Token: retryToken,
	}
}

// TestBootstrapSystem_PersonalInfoPasswordRejectedBeforeAnyWrite: the rejection
// must happen before anything is written, so nothing is left behind.
func TestBootstrapSystem_PersonalInfoPasswordRejectedBeforeAnyWrite(t *testing.T) {
	c := freshBootstrapCore(t)
	c.SetBootstrapToken(retryToken)
	ctx := context.Background()

	_, err := c.BootstrapSystem(ctx, personalInfoPasswordReq())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not contain your username, email, or display name")

	perms, err := c.storage.ListPermissions(ctx)
	require.NoError(t, err)
	assert.Empty(t, perms, "a rejected bootstrap must not have seeded any permission")
	roles, err := c.storage.ListRoles(ctx)
	require.NoError(t, err)
	assert.Empty(t, roles, "a rejected bootstrap must not have seeded any role")
	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	require.NoError(t, err)
	assert.Zero(t, total)
}

// TestBootstrapSystem_RetryAfterRejectedPasswordSucceeds is Session J's exact
// live sequence: a rejected first attempt, then a corrected password on the
// same install. Red before the fix (500: duplicate permission).
func TestBootstrapSystem_RetryAfterRejectedPasswordSucceeds(t *testing.T) {
	c := freshBootstrapCore(t)
	c.SetBootstrapToken(retryToken)
	ctx := context.Background()

	_, err := c.BootstrapSystem(ctx, personalInfoPasswordReq())
	require.Error(t, err)

	res, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.NoError(t, err, "a corrected password on the same fresh install must bootstrap")
	require.NotNil(t, res.User)
	assert.False(t, res.AlreadyInitialized)
	assert.Equal(t, "admin", res.User.Username)
}

// TestBootstrapSystem_RetryAfterPartialSeedSucceeds covers the general case: a
// failure anywhere after seeding started (not only the password check) left
// some default permissions / roles / links committed. The next attempt must
// reuse them, finish, and leave exactly one copy of each.
func TestBootstrapSystem_RetryAfterPartialSeedSucceeds(t *testing.T) {
	c := freshBootstrapCore(t)
	c.SetBootstrapToken(retryToken)
	ctx := context.Background()

	// Simulate a half-finished earlier attempt: the first two default
	// permissions, and the first default role linked to one of them.
	require.GreaterOrEqual(t, len(defaultPermissions), 2)
	var firstPerm *models.Permission
	for i, def := range defaultPermissions[:2] {
		p, err := c.storage.CreatePermission(ctx, &models.Permission{
			Name: def.Name, Description: def.Description, Resource: def.Resource, Action: def.Action,
		})
		require.NoError(t, err)
		if i == 0 {
			firstPerm = p
		}
	}
	rdef := defaultRoles[0]
	folded, err := identity.NewFoldedName(rdef.Name)
	require.NoError(t, err)
	role, err := c.storage.CreateRole(ctx, folded, rdef.Description)
	require.NoError(t, err)
	for _, name := range rdef.Permissions {
		if name == firstPerm.Name {
			require.NoError(t, c.storage.AssignPermissionToRole(ctx, role.ID, firstPerm.ID))
		}
	}

	res, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.NoError(t, err, "bootstrap must finish on top of a partial seed")
	require.NotNil(t, res.User)

	perms, err := c.storage.ListPermissions(ctx)
	require.NoError(t, err)
	assert.Len(t, perms, len(defaultPermissions), "exactly one row per default permission")
	roles, err := c.storage.ListRoles(ctx)
	require.NoError(t, err)
	assert.Len(t, roles, len(defaultRoles), "exactly one row per default role")

	got, err := c.storage.GetRolePermissions(ctx, role.ID)
	require.NoError(t, err)
	assert.Len(t, got, len(rdef.Permissions), "the reused role ends with its full default permission set, no duplicates")

	// And the admin really is an admin.
	userRoles, err := c.storage.GetUserRoles(ctx, res.User.ID)
	require.NoError(t, err)
	names := make([]string, 0, len(userRoles))
	for _, r := range userRoles {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "admin")
}
