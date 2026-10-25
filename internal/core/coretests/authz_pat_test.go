package coretests

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestPATRestriction_Allows covers the pure least-privilege filter (ADR-042):
// what a personal-access-token restriction permits, independent of any RBAC.
func TestPATRestriction_Allows(t *testing.T) {
	t.Parallel()
	proj5 := core.Scope{ProjectID: 5}
	global := core.Scope{} // project 0 — system-wide actions

	cases := []struct {
		name string
		r    *core.PATRestriction
		perm string
		sc   core.Scope
		want bool
	}{
		{"nil restriction allows anything", nil, "secrets.write", global, true},
		{"empty allowlist inherits owner", &core.PATRestriction{}, "secrets.write", proj5, true},
		{"exact permission match", &core.PATRestriction{Permissions: []string{"secrets.read"}}, "secrets.read", proj5, true},
		{"permission not in allowlist denied", &core.PATRestriction{Permissions: []string{"secrets.read"}}, "secrets.write", proj5, false},
		{"catch-all wildcard allows", &core.PATRestriction{Permissions: []string{"*"}}, "users.delete", global, true},
		{"prefix wildcard matches family", &core.PATRestriction{Permissions: []string{"secrets.*"}}, "secrets.delete", proj5, true},
		{"prefix wildcard does not cross family", &core.PATRestriction{Permissions: []string{"secrets.*"}}, "users.read", proj5, false},
		{"project-scoped token allowed within its project", &core.PATRestriction{ProjectID: 5}, "secrets.read", proj5, true},
		{"project-scoped token denied in other project", &core.PATRestriction{ProjectID: 5}, "secrets.read", core.Scope{ProjectID: 6}, false},
		{"project-scoped token denied at global scope", &core.PATRestriction{ProjectID: 5}, "users.read", global, false},
		{"both axes must pass — wrong project", &core.PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5}, "secrets.read", core.Scope{ProjectID: 6}, false},
		{"both axes must pass — wrong perm", &core.PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5}, "secrets.write", proj5, false},
		{"both axes pass", &core.PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5}, "secrets.read", proj5, true},
		// Environment axis (ADR-042 env confinement).
		{"env-scoped token allowed within its env", &core.PATRestriction{EnvironmentID: 9}, "secrets.read", core.Scope{ProjectID: 5, EnvironmentID: 9}, true},
		{"env-scoped token denied in other env", &core.PATRestriction{EnvironmentID: 9}, "secrets.read", core.Scope{ProjectID: 5, EnvironmentID: 8}, false},
		{"env-scoped token denied at project-level scope (env 0)", &core.PATRestriction{EnvironmentID: 9}, "secrets.read", proj5, false},
		{"project+env both pass", &core.PATRestriction{ProjectID: 5, EnvironmentID: 9}, "secrets.read", core.Scope{ProjectID: 5, EnvironmentID: 9}, true},
		{"project+env — wrong env denied", &core.PATRestriction{ProjectID: 5, EnvironmentID: 9}, "secrets.read", core.Scope{ProjectID: 5, EnvironmentID: 8}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.r.Allows(tc.perm, tc.sc))
		})
	}
}

// TestAuthorize_PATRestriction proves the restriction is enforced inside Authorize
// as a hard pre-gate: a disallowed permission is denied BEFORE any role resolution
// (so even a global admin's token is bounded), and an allowed permission still
// flows through to the owner's normal RBAC.
func TestAuthorize_PATRestriction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("disallowed permission denied without touching storage — even for an admin owner", func(t *testing.T) {
		ms := new(storagetest.MockStorage)
		c := core.NewKeyorixCore(ms)
		// Token may only read secrets; the owner could be a full admin, but the
		// filter denies a write before any role/admin-bypass lookup runs.
		rctx := core.WithPATRestriction(ctx, &core.PATRestriction{Permissions: []string{"secrets.read"}})

		allowed, err := c.Authorize(rctx, 1, "secrets.write", core.Scope{ProjectID: 5})
		require.NoError(t, err)
		assert.False(t, allowed)
		ms.AssertNotCalled(t, "GetUserRoleIDsAt")
		ms.AssertNotCalled(t, "RoleSetHasPermission")
	})

	t.Run("project-scoped token denied outside its project before storage", func(t *testing.T) {
		ms := new(storagetest.MockStorage)
		c := core.NewKeyorixCore(ms)
		rctx := core.WithPATRestriction(ctx, &core.PATRestriction{ProjectID: 5})

		allowed, err := c.Authorize(rctx, 1, "secrets.read", core.Scope{ProjectID: 9})
		require.NoError(t, err)
		assert.False(t, allowed)
		ms.AssertNotCalled(t, "GetUserRoleIDsAt")
	})

	t.Run("allowed permission still requires the owner to hold it", func(t *testing.T) {
		ms := new(storagetest.MockStorage)
		c := core.NewKeyorixCore(ms)
		scope := storage.Scope{ProjectID: 5}
		// Context carries the restriction, so match on Anything for ctx.
		ms.On("GetUserRoleIDsAt", mock.Anything, uint(1), scope).Return([]uint{10}, nil)
		ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(1), scope).Return([]uint{}, nil)
		// Not an admin role set (ADR-084: resolved by structural flag, not name).
		ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{10}).Return(false, nil)
		ms.On("RoleSetHasPermission", mock.Anything, []uint{10}, "secrets.read").Return(true, nil)

		rctx := core.WithPATRestriction(ctx, &core.PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5})
		allowed, err := c.Authorize(rctx, 1, "secrets.read", core.Scope{ProjectID: 5})
		require.NoError(t, err)
		assert.True(t, allowed, "the restriction permits it AND the owner's role grants it")
	})

	t.Run("no restriction on context is a no-op", func(t *testing.T) {
		ms := new(storagetest.MockStorage)
		c := core.NewKeyorixCore(ms)
		scope := storage.Scope{ProjectID: 5}
		ms.On("GetUserRoleIDsAt", ctx, uint(1), scope).Return([]uint{10}, nil)
		ms.On("GetUserGroupRoleIDsAt", ctx, uint(1), scope).Return([]uint{}, nil)
		ms.On("RoleSetBypassesPermissionChecks", ctx, []uint{10}).Return(false, nil)
		ms.On("RoleSetHasPermission", ctx, []uint{10}, "secrets.write").Return(true, nil)

		allowed, err := c.Authorize(ctx, 1, "secrets.write", core.Scope{ProjectID: 5})
		require.NoError(t, err)
		assert.True(t, allowed)
	})
}

// IsGlobalAdmin must not treat a PAT-restricted request as an unrestricted global
// admin (ADR-042) — it is an un-funnelled authz path, so the restriction is
// enforced here directly (fail-closed) rather than via Authorize.
func TestIsGlobalAdmin_PATRestrictionDeniesShortCircuit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a scoped token is never a global admin — without touching storage", func(t *testing.T) {
		ms := new(storagetest.MockStorage)
		c := core.NewKeyorixCore(ms)
		// Even though the owner (user 1) may be a global admin, a scoped token must
		// not get the unfiltered-listing short-circuit.
		rctx := core.WithPATRestriction(ctx, &core.PATRestriction{Permissions: []string{"secrets.read"}})

		isAdmin, err := c.IsGlobalAdmin(rctx, 1)
		require.NoError(t, err)
		assert.False(t, isAdmin)
		ms.AssertNotCalled(t, "GetUserRoleIDsAt")
	})

	t.Run("no restriction resolves admin normally", func(t *testing.T) {
		ms := new(storagetest.MockStorage)
		c := core.NewKeyorixCore(ms)
		ms.On("GetUserRoleIDsAt", ctx, uint(1), core.Scope{}).Return([]uint{10}, nil)
		ms.On("GetUserGroupRoleIDsAt", ctx, uint(1), core.Scope{}).Return([]uint{}, nil)
		ms.On("RoleSetBypassesPermissionChecks", ctx, []uint{10}).Return(true, nil)

		isAdmin, err := c.IsGlobalAdmin(ctx, 1)
		require.NoError(t, err)
		assert.True(t, isAdmin)
	})
}
