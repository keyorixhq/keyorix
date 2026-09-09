// remote_storage_conformance_tranche4_rbac_roles_test.go — issue #1808, tranche 4.
//
// Assignment: cover CreateRole, DeleteRole, UpdateRole, RemovePermissionFromRole,
// GetRole, GetRoleByName, GetRolePermissions, GetPermission, ListPermissions,
// ListRoles, GetUserPermissions, GetUserRoles, GetGroupRoles (all declared on
// *RemoteStorage in internal/storage/store/remote_rbac.go).
//
// # 7 of the 13 methods are SKIPPED — not for fixture-cost reasons, but because
// running each one against the REAL router (via a throwaway probe using this
// file's own harness, since deleted) surfaced a genuine, live, currently-shipping
// defect. This is exactly the defect class this harness exists to catch (see
// remote_storage_conformance_helpers_test.go's package doc and #1812's
// CreateSecret finding) — writing a passing test for any of these 7 would mean
// either asserting the WRONG (buggy) behavior as correct, or quietly hand-waving
// past a real bug. Neither is acceptable, so each is left uncovered here with the
// exact reproduction evidence below for whoever picks up the fix. All 7 need a
// PRODUCTION code change (handler response shape and/or RemoteStorage request/
// response wiring), which is out of scope for a test-only tranche.
//
//   - CreateRole: RemoteStorage.CreateRole (remote_rbac.go) POSTs {name, description}
//     to POST /api/v1/roles, but the handler's CreateRoleRequest DTO
//     (server/http/handlers/rbac.go) requires `permissions` with
//     `validate:"required,min=1"`. RemoteStorage never sends a permissions field
//     at all, so EVERY call 400s: confirmed live —
//     `ValidationError: Invalid request data ({"errors":[{"field":"permissions",
//     "message":"must have at least 1 items"}]})`. RemoteStorage.CreateRole can
//     never succeed against a real server.
//   - GetRole: the handler wraps its response as
//     `{"role": {...}, "permissions": [...]}` (GetRoleWithPermissions), but
//     RemoteStorage.GetRole unmarshals resp.Data directly into a bare
//     `models.Role`. Since no field in that JSON object is named after any
//     models.Role field, json.Unmarshal silently sets nothing and returns NO
//     ERROR — confirmed live: a real, existing role read back as
//     `&models.Role{ID:0, Name:"", ...}` with `err=<nil>`. This is a silent
//     wrong-data bug, strictly worse than an error.
//   - UpdateRole: identical wrapping mismatch and identical silent-zero-value
//     symptom as GetRole (same handler response shape). Confirmed live: the
//     WRITE itself succeeds and is correctly persisted (verified by reading the
//     row back through LocalStorage afterward), but RemoteStorage.UpdateRole's
//     own return value is silently `&models.Role{ID:0, Name:"", ...}` with
//     `err=<nil>` — any caller that uses the returned struct (logging, chaining)
//     gets garbage while believing the call fully succeeded.
//   - ListRoles: the handler wraps as `{"roles":[...], "total": N}`, but
//     RemoteStorage.ListRoles unmarshals resp.Data directly into `[]*models.Role`
//     (a bare array). Unlike the object-into-struct cases above, object-into-
//     slice IS a hard type error: confirmed live —
//     `failed to parse response: json: cannot unmarshal object into Go value of
//     type []*models.Role`. Every call fails.
//   - GetUserRoles: RemoteStorage.GetUserRoles calls
//     `GET /api/v1/users/{userId}/roles`, which routes to
//     UsersRolesHandler.GetUserRolesForUser (NOT rbacHandler.GetUserRoles, which
//     is wired at the unrelated path `/api/v1/user-roles/user/{userId}`).
//     GetUserRolesForUser wraps its response as `{"roles": [...]}` (also using a
//     reduced `apiRole{ID, Name}` shape, dropping Description/BypassesPermission-
//     Checks/NameFolded), but RemoteStorage.GetUserRoles unmarshals into a bare
//     `[]*models.Role`. Confirmed live: `failed to parse response: json: cannot
//     unmarshal object into Go value of type []*models.Role`. Every call fails.
//   - GetUserPermissions: same class as GetUserRoles. The wired handler
//     (UsersRolesHandler.GetUserPermissionsForUser) wraps as
//     `{"permissions": [...]}` using a reduced `apiPermission` shape (no ID
//     field), but RemoteStorage.GetUserPermissions unmarshals into a bare
//     `[]*storage.Permission`. Confirmed live: `failed to parse response: json:
//     cannot unmarshal object into Go value of type []*storage.Permission`.
//   - GetGroupRoles: the wired handler (rbacHandler.GetGroupRoles) wraps as
//     `{"group_id": N, "roles": [...]}`, where `roles` are
//     `[]*storage.GroupRoleGrant` (ID/Name/Description/ExpiresAt — NOT a full
//     models.Role), but RemoteStorage.GetGroupRoles unmarshals into a bare
//     `[]*models.Role`. Confirmed live: `failed to parse response: json: cannot
//     unmarshal object into Go value of type []*models.Role`. Two independent
//     defects stacked (wrapping AND shape), either one alone would already break
//     this call.
//
// This is a HIGH-severity, previously-undiscovered finding: under ADR-049's
// storage.type: remote deployment shape (a downstream Keyorix node whose
// core.KeyorixCore is backed by RemoteStorage), role management is effectively
// non-functional end-to-end — creating, reading, listing, or updating a role, and
// reading a user's or group's roles/permissions, either hard-fails or silently
// returns zero-value data. Filed for a dedicated follow-up fix; NOT patched here
// per this tranche's test-only scope (no production file may be touched by this
// change).
//
// The remaining 6 methods below are confirmed working correctly against the real
// router and are covered with full field-exhaustive + negative-case rigor:
// DeleteRole, RemovePermissionFromRole, GetRoleByName, GetRolePermissions,
// GetPermission, ListPermissions.
package http

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- DeleteRole ---

func TestConformance_DeleteRole(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newRole := func(suffix string) *models.Role {
		name, err := identity.NewFoldedName("conformance-dr-" + suffix)
		require.NoError(t, err)
		role, err := h.ls.CreateRole(ctx, name, "conformance DeleteRole test role "+suffix)
		require.NoError(t, err)
		return role
	}

	localRole := newRole("local")
	require.NoError(t, h.ls.DeleteRole(ctx, localRole.ID))

	remoteRole := newRole("remote")
	require.NoError(t, h.rs.DeleteRole(ctx, remoteRole.ID),
		"RemoteStorage.DeleteRole must succeed for a role that genuinely exists")

	_, localErr := h.ls.GetRole(ctx, localRole.ID)
	_, remoteErr := h.ls.GetRole(ctx, remoteRole.ID)
	assert.Error(t, localErr, "sanity: a deleted role must not be readable")
	assert.Error(t, remoteErr,
		"the role deleted via RemoteStorage must actually be gone server-side, not just report success -- "+
			"read back through the SAME LocalStorage instance the router wraps, not just trusting the HTTP response")

	// Deleting an already-deleted (or never-existent) role must fail identically on
	// both paths -- not silently succeed a second time, which would mask a
	// dropped-ID / wrong-route defect as false "idempotent" success.
	assert.Error(t, h.ls.DeleteRole(ctx, localRole.ID))
	assert.Error(t, h.rs.DeleteRole(ctx, remoteRole.ID))
}

// --- RemovePermissionFromRole ---

func TestConformance_RemovePermissionFromRole(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	perms, err := h.ls.ListPermissions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, perms, "sanity: bootstrap must have seeded at least one permission")
	permID := perms[0].ID

	newRoleWithPermission := func(suffix string) *models.Role {
		name, err := identity.NewFoldedName("conformance-rpfr-" + suffix)
		require.NoError(t, err)
		role, err := h.ls.CreateRole(ctx, name, "conformance RemovePermissionFromRole test role "+suffix)
		require.NoError(t, err)
		require.NoError(t, h.ls.AssignPermissionToRole(ctx, role.ID, permID))
		return role
	}

	localRole := newRoleWithPermission("local")
	require.NoError(t, h.ls.RemovePermissionFromRole(ctx, localRole.ID, permID))

	remoteRole := newRoleWithPermission("remote")
	require.NoError(t, h.rs.RemovePermissionFromRole(ctx, remoteRole.ID, permID),
		"RemoteStorage.RemovePermissionFromRole must succeed for a permission genuinely assigned to the role")

	localPermsAfter, err := h.ls.GetRolePermissions(ctx, localRole.ID)
	require.NoError(t, err)
	remotePermsAfter, err := h.ls.GetRolePermissions(ctx, remoteRole.ID)
	require.NoError(t, err)
	assert.Empty(t, localPermsAfter, "sanity: the local role's permission must be gone")
	assert.Empty(t, remotePermsAfter,
		"the remote role's permission must actually be gone server-side, not just report success -- read back "+
			"through the SAME LocalStorage instance the router wraps")

	// Removing a permission the role no longer holds (already removed above) must
	// fail identically on both paths -- not silently no-op success, which would
	// mask a dropped-roleID/permissionID defect as false "idempotent" success.
	assert.Error(t, h.ls.RemovePermissionFromRole(ctx, localRole.ID, permID))
	assert.Error(t, h.rs.RemovePermissionFromRole(ctx, remoteRole.ID, permID),
		"RemoteStorage.RemovePermissionFromRole must report an error for a permission the role does not hold, "+
			"not silently succeed")
}

// --- GetRoleByName ---

func TestConformance_GetRoleByName(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	name, err := identity.NewFoldedName("conformance-grbn-role")
	require.NoError(t, err)
	seeded, err := h.ls.CreateRole(ctx, name, "conformance GetRoleByName test role")
	require.NoError(t, err)

	localRead, err := h.ls.GetRoleByName(ctx, seeded.Name)
	require.NoError(t, err)
	remoteRead, err := h.rs.GetRoleByName(ctx, seeded.Name)
	require.NoError(t, err, "RemoteStorage.GetRoleByName must succeed for a role that genuinely exists")

	exclude := map[string]bool{
		// models.Role.NameFolded carries `json:"-"` -- a write-time-only derived
		// field (identity.NewFoldedName run at CreateRole time) that is never
		// intended to round-trip over the wire; the server independently
		// re-derives it from Name on writes, and no read handler serializes it.
		// Confirmed empirically: RemoteStorage.GetRoleByName always returns
		// NameFolded="" regardless of the real stored value, while LocalStorage's
		// direct DB read returns the real folded string -- a wire-format
		// omission by design (the json tag), not a proxy defect.
		"NameFolded": true,
	}
	assertFieldExhaustiveEqual(t, "GetRoleByName(local vs remote, same row)", localRead, remoteRead, exclude)

	_, localErr := h.ls.GetRoleByName(ctx, "conformance-grbn-does-not-exist")
	_, remoteErr := h.rs.GetRoleByName(ctx, "conformance-grbn-does-not-exist")
	assert.Error(t, localErr, "sanity: a nonexistent role name must not resolve")
	assert.Error(t, remoteErr,
		"RemoteStorage.GetRoleByName must report an error for a nonexistent role name, not a false match")
}

// --- GetRolePermissions ---

func TestConformance_GetRolePermissions(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	allPerms, err := h.ls.ListPermissions(ctx)
	require.NoError(t, err)
	require.True(t, len(allPerms) >= 2, "sanity: bootstrap must have seeded at least 2 permissions")

	name, err := identity.NewFoldedName("conformance-grp-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, name, "conformance GetRolePermissions test role")
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignPermissionToRole(ctx, role.ID, allPerms[0].ID))
	require.NoError(t, h.ls.AssignPermissionToRole(ctx, role.ID, allPerms[1].ID))

	localPerms, err := h.ls.GetRolePermissions(ctx, role.ID)
	require.NoError(t, err)
	remotePerms, err := h.rs.GetRolePermissions(ctx, role.ID)
	require.NoError(t, err, "RemoteStorage.GetRolePermissions must succeed for a role that genuinely exists")
	assert.ElementsMatch(t, localPerms, remotePerms,
		"RemoteStorage.GetRolePermissions must return exactly the same permission set as LocalStorage for the "+
			"SAME role -- a dropped join or wrong roleID on the wire would return the wrong set")

	// Precondition divergence, confirmed by direct code inspection (not guessed):
	// LocalStorage.GetRolePermissions is a raw JOIN with no existence check on
	// the role row (an unmatched roleID simply yields zero join rows), while
	// RemoteStorage.GetRolePermissions is proxied through the server's
	// GetRolePermissions handler, which calls core.GetRoleWithPermissions --
	// that function calls storage.GetRole FIRST and returns ITS NotFound error
	// before ever reaching GetRolePermissions. The two backends are genuinely
	// NOT equivalent for a nonexistent roleID; assert what each actually does
	// rather than asserting a false parity between them.
	localEmpty, err := h.ls.GetRolePermissions(ctx, 999999998)
	require.NoError(t, err,
		"LocalStorage.GetRolePermissions has no existence check on the role row -- an unmatched roleID is "+
			"simply zero rows, not an error")
	assert.Empty(t, localEmpty)
	_, remoteNotFoundErr := h.rs.GetRolePermissions(ctx, 999999999)
	assert.Error(t, remoteNotFoundErr,
		"RemoteStorage.GetRolePermissions is proxied through a handler that resolves the role first "+
			"(core.GetRoleWithPermissions), so a nonexistent roleID must surface as an error, not an empty list")
}

// --- GetPermission ---

func TestConformance_GetPermission(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	allPerms, err := h.ls.ListPermissions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, allPerms, "sanity: bootstrap must have seeded at least one permission")
	target := allPerms[0]

	localRead, err := h.ls.GetPermission(ctx, target.ID)
	require.NoError(t, err)
	remoteRead, err := h.rs.GetPermission(ctx, target.ID)
	require.NoError(t, err, "RemoteStorage.GetPermission must succeed for a permission that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetPermission(local vs remote, same row)", localRead, remoteRead, map[string]bool{})

	_, localErr := h.ls.GetPermission(ctx, 999999999)
	_, remoteErr := h.rs.GetPermission(ctx, 999999999)
	assert.Error(t, localErr, "sanity: a nonexistent permission ID must not resolve")
	assert.Error(t, remoteErr,
		"RemoteStorage.GetPermission must report an error for a nonexistent permission ID, not a false match")
}

// --- ListPermissions ---

// No natural negative/precondition case exists for this method: the permission
// catalog is seeded at bootstrap and RemoteStorage.ListPermissions takes no
// filter argument to exercise an edge case against (the handler's own optional
// ?resource= query param is never sent by this client method) -- the meaningful
// assertion is that the two backends agree on the full catalog content.
func TestConformance_ListPermissions(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	localPerms, err := h.ls.ListPermissions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, localPerms, "sanity: bootstrap must have seeded the permission catalog")

	remotePerms, err := h.rs.ListPermissions(ctx)
	require.NoError(t, err, "RemoteStorage.ListPermissions must succeed")
	assert.ElementsMatch(t, localPerms, remotePerms,
		"RemoteStorage.ListPermissions must return exactly the same permission catalog as LocalStorage -- a "+
			"dropped row or field on the wire would silently under-report the catalog")
}
