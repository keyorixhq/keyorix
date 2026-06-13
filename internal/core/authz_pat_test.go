package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestPATRestriction_Allows covers the pure least-privilege filter (ADR-042):
// what a personal-access-token restriction permits, independent of any RBAC.
func TestPATRestriction_Allows(t *testing.T) {
	proj5 := Scope{ProjectID: 5}
	global := Scope{} // project 0 — system-wide actions

	cases := []struct {
		name string
		r    *PATRestriction
		perm string
		sc   Scope
		want bool
	}{
		{"nil restriction allows anything", nil, "secrets.write", global, true},
		{"empty allowlist inherits owner", &PATRestriction{}, "secrets.write", proj5, true},
		{"exact permission match", &PATRestriction{Permissions: []string{"secrets.read"}}, "secrets.read", proj5, true},
		{"permission not in allowlist denied", &PATRestriction{Permissions: []string{"secrets.read"}}, "secrets.write", proj5, false},
		{"catch-all wildcard allows", &PATRestriction{Permissions: []string{"*"}}, "users.delete", global, true},
		{"prefix wildcard matches family", &PATRestriction{Permissions: []string{"secrets.*"}}, "secrets.delete", proj5, true},
		{"prefix wildcard does not cross family", &PATRestriction{Permissions: []string{"secrets.*"}}, "users.read", proj5, false},
		{"project-scoped token allowed within its project", &PATRestriction{ProjectID: 5}, "secrets.read", proj5, true},
		{"project-scoped token denied in other project", &PATRestriction{ProjectID: 5}, "secrets.read", Scope{ProjectID: 6}, false},
		{"project-scoped token denied at global scope", &PATRestriction{ProjectID: 5}, "users.read", global, false},
		{"both axes must pass — wrong project", &PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5}, "secrets.read", Scope{ProjectID: 6}, false},
		{"both axes must pass — wrong perm", &PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5}, "secrets.write", proj5, false},
		{"both axes pass", &PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5}, "secrets.read", proj5, true},
		// Environment axis (ADR-042 env confinement).
		{"env-scoped token allowed within its env", &PATRestriction{EnvironmentID: 9}, "secrets.read", Scope{ProjectID: 5, EnvironmentID: 9}, true},
		{"env-scoped token denied in other env", &PATRestriction{EnvironmentID: 9}, "secrets.read", Scope{ProjectID: 5, EnvironmentID: 8}, false},
		{"env-scoped token denied at project-level scope (env 0)", &PATRestriction{EnvironmentID: 9}, "secrets.read", proj5, false},
		{"project+env both pass", &PATRestriction{ProjectID: 5, EnvironmentID: 9}, "secrets.read", Scope{ProjectID: 5, EnvironmentID: 9}, true},
		{"project+env — wrong env denied", &PATRestriction{ProjectID: 5, EnvironmentID: 9}, "secrets.read", Scope{ProjectID: 5, EnvironmentID: 8}, false},
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
	ctx := context.Background()

	t.Run("disallowed permission denied without touching storage — even for an admin owner", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		// Token may only read secrets; the owner could be a full admin, but the
		// filter denies a write before any role/admin-bypass lookup runs.
		rctx := WithPATRestriction(ctx, &PATRestriction{Permissions: []string{"secrets.read"}})

		allowed, err := c.Authorize(rctx, 1, "secrets.write", Scope{ProjectID: 5})
		require.NoError(t, err)
		assert.False(t, allowed)
		ms.AssertNotCalled(t, "GetUserRoleIDsAt")
		ms.AssertNotCalled(t, "RoleSetHasPermission")
	})

	t.Run("project-scoped token denied outside its project before storage", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		rctx := WithPATRestriction(ctx, &PATRestriction{ProjectID: 5})

		allowed, err := c.Authorize(rctx, 1, "secrets.read", Scope{ProjectID: 9})
		require.NoError(t, err)
		assert.False(t, allowed)
		ms.AssertNotCalled(t, "GetUserRoleIDsAt")
	})

	t.Run("allowed permission still requires the owner to hold it", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		scope := storage.Scope{ProjectID: 5}
		// Context carries the restriction, so match on Anything for ctx.
		ms.On("GetUserRoleIDsAt", mock.Anything, uint(1), scope).Return([]uint{10}, nil)
		ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(1), scope).Return([]uint{}, nil)
		// Not an admin role set — every admin-name lookup misses.
		ms.On("GetRoleByName", mock.Anything, "super_admin").Return(nil, assert.AnError)
		ms.On("GetRoleByName", mock.Anything, "admin").Return(nil, assert.AnError)
		ms.On("GetRoleByName", mock.Anything, "system_admin").Return(nil, assert.AnError)
		ms.On("GetRoleByName", mock.Anything, "project_admin").Return(nil, assert.AnError)
		ms.On("RoleSetHasPermission", mock.Anything, []uint{10}, "secrets.read").Return(true, nil)

		rctx := WithPATRestriction(ctx, &PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5})
		allowed, err := c.Authorize(rctx, 1, "secrets.read", Scope{ProjectID: 5})
		require.NoError(t, err)
		assert.True(t, allowed, "the restriction permits it AND the owner's role grants it")
	})

	t.Run("no restriction on context is a no-op", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		scope := storage.Scope{ProjectID: 5}
		ms.On("GetUserRoleIDsAt", ctx, uint(1), scope).Return([]uint{10}, nil)
		ms.On("GetUserGroupRoleIDsAt", ctx, uint(1), scope).Return([]uint{}, nil)
		ms.On("GetRoleByName", ctx, "super_admin").Return(nil, assert.AnError)
		ms.On("GetRoleByName", ctx, "admin").Return(nil, assert.AnError)
		ms.On("GetRoleByName", ctx, "system_admin").Return(nil, assert.AnError)
		ms.On("GetRoleByName", ctx, "project_admin").Return(nil, assert.AnError)
		ms.On("RoleSetHasPermission", ctx, []uint{10}, "secrets.write").Return(true, nil)

		allowed, err := c.Authorize(ctx, 1, "secrets.write", Scope{ProjectID: 5})
		require.NoError(t, err)
		assert.True(t, allowed)
	})
}

// IsGlobalAdmin must not treat a PAT-restricted request as an unrestricted global
// admin (ADR-042) — it is an un-funnelled authz path, so the restriction is
// enforced here directly (fail-closed) rather than via Authorize.
func TestIsGlobalAdmin_PATRestrictionDeniesShortCircuit(t *testing.T) {
	ctx := context.Background()

	t.Run("a scoped token is never a global admin — without touching storage", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		// Even though the owner (user 1) may be a global admin, a scoped token must
		// not get the unfiltered-listing short-circuit.
		rctx := WithPATRestriction(ctx, &PATRestriction{Permissions: []string{"secrets.read"}})

		isAdmin, err := c.IsGlobalAdmin(rctx, 1)
		require.NoError(t, err)
		assert.False(t, isAdmin)
		ms.AssertNotCalled(t, "GetUserRoleIDsAt")
	})

	t.Run("no restriction resolves admin normally", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetUserRoleIDsAt", ctx, uint(1), Scope{}).Return([]uint{10}, nil)
		ms.On("GetUserGroupRoleIDsAt", ctx, uint(1), Scope{}).Return([]uint{}, nil)
		ms.On("GetRoleByName", ctx, "super_admin").Return(&models.Role{ID: 10, Name: "super_admin"}, nil)

		isAdmin, err := c.IsGlobalAdmin(ctx, 1)
		require.NoError(t, err)
		assert.True(t, isAdmin)
	})
}
