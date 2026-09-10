// remote_storage_conformance_tranche5_rbac_audit_test.go — issue #1808, tranche 5.
//
// Assignment: cover the 7 methods tranche 4's own header documented as SKIPPED
// because the real router demonstrably broke them at the time (GetRole,
// UpdateRole, ListRoles, GetUserRoles, GetUserPermissions, GetGroupRoles from
// internal/storage/store/remote_rbac.go) plus GetAuditLogs
// (internal/storage/store/remote_audit.go), now that PR #1832
// ("fix(remote): unwrap response envelopes and send snake_case request
// bodies") has landed. Every claim below was re-verified directly against the
// CURRENT source (not trusted from either tranche 4's now-stale bug writeup or
// #1832's own commit message, which itself turned out to contain one
// inaccurate claim — see ListRoles below) and, for every field-shape claim,
// against a live throwaway probe run against the real router before writing
// the corresponding assertion.
//
// # 6 of 7 are fixed and covered here with field-exhaustive + negative/
// precondition rigor: GetRole, UpdateRole, ListRoles, GetUserRoles,
// GetUserPermissions, GetGroupRoles.
//
// # GetAuditLogs is SKIPPED -- the envelope-key fix is real, but a live probe
// against the real router found a SIBLING defect the fix did not touch, and
// writing a field-exhaustive test would fail on real, confirmed evidence
// rather than a fake pass:
//
//	RemoteStorage.GetAuditLogs (remote_audit.go) unmarshals the "logs" array
//	into []*models.AuditEvent -- a struct with NO json tags at all (default
//	Go field-name matching). The real handler (server/http/handlers/audit.go)
//	sends each entry as AuditLogEntry, which DOES carry explicit snake_case
//	tags (event_type, actor_type, timestamp, impersonated_by, acting_as).
//	encoding/json's fallback matching is case-INSENSITIVE, not snake_case-to-
//	PascalCase-folding, so a wire key like "event_type" does not match the Go
//	field "EventType" at all (verified empirically: json.Unmarshal of
//	{"event_type":"x", ...} into a struct with an EventType field leaves it
//	"", with err == nil). A throwaway probe seeding one real audit event via
//	h.ls.LogAuditEvent and reading it back through both h.ls.GetAuditLogs and
//	h.rs.GetAuditLogs against the real router confirmed this live:
//
//	  localTotal=3 remoteTotal=3 localLen=3 remoteLen=3   (counts/lengths agree -- #1832's fix is real)
//	  local[0] .EventType="machine_identity.token_issued" .UserID=<ptr> .ProjectID=<ptr>
//	           .EventTime=2026-09-10T11:53:53Z .ActorType="user" .EntryHash="886c52c5..."
//	  remote[0].EventType=""                              .UserID=<nil> .ProjectID=<nil>
//	           .EventTime=0001-01-01T00:00:00Z .ActorType=""            .EntryHash=""
//
//	Only ID, Description, and Impersonation survive (their wire keys happen to
//	differ from the Go field name only in case, with no underscore, so the
//	case-insensitive fallback works for exactly those three by accident).
//	EventType/EventTime/ActorType/UserID/ProjectID/SecretNodeID/IPAddress/
//	Success/MachineIdentityID/PrevHash/EntryHash are ALL silently zeroed, with
//	no error -- for a compliance/audit product, a query that returns the right
//	COUNT of the right ROWS but with "what happened," "when," and "who" blanked
//	out is arguably worse than the pre-#1832 empty-list bug, precisely because
//	len(events) > 0 now passes a naive check. Writing this method's test
//	honestly requires either asserting that near-total field loss as correct
//	(unacceptable) or failing the build on a known, already-filed gap
//	(disproportionate to a test-only tranche with no production file in
//	scope). Filed as a follow-up; not silently patched over here.
//
// # A correction to #1832's own commit message, made because this tranche's
// brief explicitly required verifying rather than trusting it: the commit
// message groups ListRoles with GetUserRoles/GetGroupRoles as projecting
// through "handlers.apiRole" (ID+Name only, Description/permissions empty).
// That is TRUE for GetUserRoles but FALSE for ListRoles: `git log -p --follow`
// on server/http/handlers/rbac.go shows ListRoles has called
// core.ListRolesWithPermissions (returning the FULL embedded models.Role plus
// its permission set) since that function was introduced, with no apiRole
// variant ever in its history, and a live probe confirms ListRoles returns
// full field fidelity (Name/Description/BypassesPermissionChecks all present)
// alongside GetUserRoles' genuinely-reduced ID+Name-only shape from the SAME
// probe run. The ListRoles test below is written against the verified
// behavior, not the commit message's claim.
package http

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// nameFoldedExclude is shared by every RBAC comparison below: models.Role.NameFolded
// carries `json:"-"` (internal/storage/models/models.go) -- a write-time-only derived
// field that is never intended to round-trip over the wire on ANY route, so the remote
// side always observes "" regardless of the real stored value. This is the exact
// exclusion tranche 4's TestConformance_GetRoleByName already established for the same
// field on a different route; every route below hits the identical json:"-" tag on the
// identical struct, so the same justification applies verbatim.
var nameFoldedExclude = map[string]bool{"NameFolded": true}

// --- GetRole ---

func TestConformance_GetRole(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	name, err := identity.NewFoldedName("conformance-gr-role")
	require.NoError(t, err)
	seeded, err := h.ls.CreateRole(ctx, name, "conformance GetRole test role")
	require.NoError(t, err)

	localRead, err := h.ls.GetRole(ctx, seeded.ID)
	require.NoError(t, err)
	remoteRead, err := h.rs.GetRole(ctx, seeded.ID)
	require.NoError(t, err, "RemoteStorage.GetRole must succeed for a role that genuinely exists")

	// GetRole's response is now correctly unwrapped from {"role": {...}} (#1832) into the
	// full underlying models.Role (server/http/handlers/rbac.go's GetRole calls
	// GetRoleWithPermissions, which returns the role storage.GetRole itself returned, not a
	// reduced projection) -- confirmed by direct code read and a live probe. Every field
	// round-trips except NameFolded.
	assertFieldExhaustiveEqual(t, "GetRole(local vs remote, same row)", localRead, remoteRead, nameFoldedExclude)

	_, localErr := h.ls.GetRole(ctx, 999999999)
	_, remoteErr := h.rs.GetRole(ctx, 999999999)
	assert.Error(t, localErr, "sanity: a nonexistent role ID must not resolve")
	assert.Error(t, remoteErr,
		"RemoteStorage.GetRole must report an error for a nonexistent role ID -- pre-#1832 this silently "+
			"returned a zero-valued &models.Role{} with err == nil, strictly worse than an error")
}

// --- UpdateRole ---

func TestConformance_UpdateRole(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newRole := func(suffix string) *models.Role {
		name, err := identity.NewFoldedName("conformance-ur-" + suffix)
		require.NoError(t, err)
		role, err := h.ls.CreateRole(ctx, name, "conformance UpdateRole test role "+suffix)
		require.NoError(t, err)
		return role
	}

	// UpdateRoleRequest (server/http/handlers/rbac.go) only carries description+permissions
	// -- Name has no field mapping to models.Role.Name at all (#1494's closure:
	// TestUpdateRoleRequest_CarriesNoNameField), so only Description is exercised here; a
	// Name change sent over RemoteStorage.UpdateRole would be silently ignored server-side,
	// which is a documented, deliberate design invariant, not something this wire-fidelity
	// test needs to re-prove.
	localRole := newRole("local")
	localRole.Description = "conformance updated description local"
	localUpdated, err := h.ls.UpdateRole(ctx, localRole)
	require.NoError(t, err)
	assert.Equal(t, "conformance updated description local", localUpdated.Description,
		"sanity: LocalStorage.UpdateRole's own return value must reflect the update")

	remoteRole := newRole("remote")
	remoteRole.Description = "conformance updated description remote"
	remoteUpdated, err := h.rs.UpdateRole(ctx, remoteRole)
	require.NoError(t, err, "RemoteStorage.UpdateRole must succeed for a genuine, non-built-in role")

	// The historical bug this proves fixed (tranche 4's own writeup): RemoteStorage.UpdateRole
	// used to unmarshal the WRAPPED {"role": {...}} response directly into a bare models.Role,
	// silently matching no field and returning &models.Role{ID:0, Name:"", ...} with err == nil
	// -- succeeding while lying about what it returned. Prove the fix by field-exhaustively
	// comparing RemoteStorage.UpdateRole's OWN return value against the SAME row (same ID) read
	// back independently through LocalStorage: if the response were still silently zero-valued,
	// this comparison would catch it immediately (ID/Name/Description would all mismatch).
	persisted, err := h.ls.GetRole(ctx, remoteRole.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "UpdateRole(RemoteStorage's own return value vs the persisted row)", persisted, remoteUpdated, nameFoldedExclude)
	assert.Equal(t, "conformance updated description remote", remoteUpdated.Description,
		"RemoteStorage.UpdateRole's return value must reflect the NEW description, not a stale or zero one")

	// Precondition divergence, confirmed by direct code inspection AND a live probe (not
	// guessed): LocalStorage.UpdateRole (local_rbac.go) is a bare `db.Save(role)` with NO
	// built-in-role guard at the storage layer -- it will happily overwrite "admin"'s row.
	// RemoteStorage.UpdateRole is proxied through the HTTP handler, which calls
	// core.UpdateRole (internal/core/rbac_roles.go), and THAT function's
	// IsBuiltinRole(role.Name) check rejects the mutation with 403 before it ever reaches
	// storage. The two backends are genuinely NOT equivalent for a built-in role's update --
	// assert what each actually does, mirroring GetRolePermissions' documented
	// LocalStorage-vs-core divergence in tranche 4, rather than asserting a false parity.
	adminRole, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	originalAdminDescription := adminRole.Description

	adminRole.Description = "conformance builtin-role bypass attempt (local)"
	_, err = h.ls.UpdateRole(ctx, adminRole)
	require.NoError(t, err,
		"LocalStorage.UpdateRole has no built-in-role guard at the storage layer -- confirmed by direct "+
			"inspection of local_rbac.go's bare Save call")

	adminRoleForRemote, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	adminRoleForRemote.Description = "conformance builtin-role bypass attempt (remote)"
	_, err = h.rs.UpdateRole(ctx, adminRoleForRemote)
	assert.Error(t, err,
		"RemoteStorage.UpdateRole must refuse to update a built-in role -- it is proxied through "+
			"core.UpdateRole, which enforces IsBuiltinRole even though the raw storage layer itself has no "+
			"such guard")

	stillAdmin, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	assert.NotEqual(t, originalAdminDescription, stillAdmin.Description,
		"sanity: LocalStorage's own unguarded update above DID take effect")
	assert.NotEqual(t, "conformance builtin-role bypass attempt (remote)", stillAdmin.Description,
		"RemoteStorage's rejected update must NOT have taken effect server-side")
}

// --- ListRoles ---

func TestConformance_ListRoles(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	name, err := identity.NewFoldedName("conformance-lr-role")
	require.NoError(t, err)
	seeded, err := h.ls.CreateRole(ctx, name, "conformance ListRoles test role")
	require.NoError(t, err)
	perms, err := h.ls.ListPermissions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, perms, "sanity: bootstrap must have seeded at least one permission")
	require.NoError(t, h.ls.AssignPermissionToRole(ctx, seeded.ID, perms[0].ID))

	localRoles, err := h.ls.ListRoles(ctx)
	require.NoError(t, err)
	remoteRoles, err := h.rs.ListRoles(ctx)
	require.NoError(t, err, "RemoteStorage.ListRoles must succeed")

	localByID := make(map[uint]*models.Role, len(localRoles))
	for _, r := range localRoles {
		localByID[r.ID] = r
	}
	remoteByID := make(map[uint]*models.Role, len(remoteRoles))
	for _, r := range remoteRoles {
		remoteByID[r.ID] = r
	}
	require.Equal(t, len(localByID), len(remoteByID),
		"RemoteStorage.ListRoles must return exactly the same role SET as LocalStorage -- a dropped or "+
			"duplicated row would silently mis-report the catalog")

	// See this file's package doc for why ListRoles is NOT reduced to apiRole (that claim in
	// #1832's own commit message is verified false for this specific method): the handler
	// calls ListRolesWithPermissions, returning the full embedded models.Role, so every
	// field round-trips except NameFolded, same as GetRole/UpdateRole above.
	for id, lr := range localByID {
		rr, ok := remoteByID[id]
		require.True(t, ok, "role id %d present in LocalStorage.ListRoles but missing from RemoteStorage.ListRoles", id)
		assertFieldExhaustiveEqual(t, fmt.Sprintf("ListRoles(local vs remote, role id %d)", id), lr, rr, nameFoldedExclude)
	}
}

// --- GetUserRoles ---

func TestConformance_GetUserRoles(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	localRoles, err := h.ls.GetUserRoles(ctx, h.adminUserID)
	require.NoError(t, err)
	require.NotEmpty(t, localRoles, "sanity: the harness's admin user must hold at least one role")

	remoteRoles, err := h.rs.GetUserRoles(ctx, h.adminUserID)
	require.NoError(t, err, "RemoteStorage.GetUserRoles must succeed")
	require.Len(t, remoteRoles, len(localRoles),
		"RemoteStorage.GetUserRoles must return the same NUMBER of role grants as LocalStorage")

	// GetUserRoles' wire response is projected through handlers.apiRole
	// (server/http/handlers/users_roles.go:23-26,65-68), which carries ONLY id+name --
	// confirmed by direct code read AND a live probe against the real router: Description,
	// BypassesPermissionChecks, and NameFolded all come back zero-valued on the remote side
	// regardless of the real stored role (the harness's admin role genuinely has
	// BypassesPermissionChecks=true and a non-empty Description locally). This is a
	// documented, deliberate server-side projection (#1832's own commit message records
	// exactly this class for this method), not a proxy defect -- exclude exactly these
	// three fields, nothing else.
	exclude := map[string]bool{"Description": true, "BypassesPermissionChecks": true, "NameFolded": true}
	localByID := make(map[uint]*models.Role, len(localRoles))
	for _, r := range localRoles {
		localByID[r.ID] = r
	}
	for _, rr := range remoteRoles {
		lr, ok := localByID[rr.ID]
		require.True(t, ok, "role id %d returned by RemoteStorage.GetUserRoles but not by LocalStorage", rr.ID)
		assertFieldExhaustiveEqual(t, fmt.Sprintf("GetUserRoles(local vs remote, role id %d)", rr.ID), lr, rr, exclude)
	}

	// Precondition: LocalStorage.GetUserRoles has no existence check on userID (a raw JOIN
	// that simply yields zero rows for an unmatched user) -- confirmed by direct read of
	// local_rbac.go. GetUserRolesByID (the core function the HTTP handler calls) proxies
	// straight to storage.GetUserRoles, the SAME shape of raw JOIN with no existence check --
	// so, unlike GetRolePermissions' divergent nonexistent-ID case in tranche 4, both
	// backends genuinely AGREE here: an empty list, not an error.
	localEmpty, err := h.ls.GetUserRoles(ctx, 999999999)
	require.NoError(t, err)
	assert.Empty(t, localEmpty)
	remoteEmpty, err := h.rs.GetUserRoles(ctx, 999999999)
	require.NoError(t, err,
		"RemoteStorage.GetUserRoles must not error for a nonexistent userID -- GetUserRolesByID never "+
			"returns not-found, it simply returns an empty slice, matching LocalStorage")
	assert.Empty(t, remoteEmpty)
}

// --- GetUserPermissions ---

func TestConformance_GetUserPermissions(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	localPerms, err := h.ls.GetUserPermissions(ctx, h.adminUserID)
	require.NoError(t, err)
	require.NotEmpty(t, localPerms, "sanity: the harness's admin user must hold at least one direct permission")

	remotePerms, err := h.rs.GetUserPermissions(ctx, h.adminUserID)
	require.NoError(t, err, "RemoteStorage.GetUserPermissions must succeed")
	require.Len(t, remotePerms, len(localPerms),
		"RemoteStorage.GetUserPermissions must return the same NUMBER of permissions as LocalStorage")

	// GetUserPermissions' wire response is projected through handlers.apiPermission
	// (server/http/handlers/users_roles.go:91-96,137-140), whose struct has NO ID field at
	// all -- confirmed by direct code read AND a live probe: every permission returned by
	// RemoteStorage.GetUserPermissions has ID 0. #1832's own commit message documents this
	// exact projection. Name/Resource/Action/Description carry EXACT-matching json tags on
	// both storage.Permission and apiPermission, so those four fields are expected to (and,
	// per the probe, do) round-trip with full fidelity -- only ID is excluded.
	exclude := map[string]bool{"ID": true}
	localByName := make(map[string]*coreStorage.Permission, len(localPerms))
	for _, p := range localPerms {
		localByName[p.Name] = p
	}
	for _, rp := range remotePerms {
		lp, ok := localByName[rp.Name]
		require.True(t, ok, "permission %q returned by RemoteStorage.GetUserPermissions but not by LocalStorage", rp.Name)
		assertFieldExhaustiveEqual(t, fmt.Sprintf("GetUserPermissions(local vs remote, permission %q)", rp.Name), lp, rp, exclude)
	}

	// Precondition: same no-existence-check shape as GetUserRoles above -- confirmed by
	// direct read of GetUserPermissionsByID (calls storage.GetUserPermissions +
	// storage.GetUserGroupPermissions, neither of which resolves the user row first).
	localEmpty, err := h.ls.GetUserPermissions(ctx, 999999999)
	require.NoError(t, err)
	assert.Empty(t, localEmpty)
	remoteEmpty, err := h.rs.GetUserPermissions(ctx, 999999999)
	require.NoError(t, err,
		"RemoteStorage.GetUserPermissions must not error for a nonexistent userID, matching LocalStorage's "+
			"own no-existence-check behavior")
	assert.Empty(t, remoteEmpty)
}

// --- GetGroupRoles ---

func TestConformance_GetGroupRoles(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newGroup := func(suffix string) *models.Group {
		name, err := identity.NewFoldedName("conformance-ggr-" + suffix)
		require.NoError(t, err)
		group, err := h.ls.CreateGroup(ctx, &models.Group{Name: name.Display(), NameFolded: name.Folded()})
		require.NoError(t, err)
		return group
	}
	name, err := identity.NewFoldedName("conformance-ggr-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, name, "conformance GetGroupRoles test role")
	require.NoError(t, err)

	localGroup := newGroup("local")
	require.NoError(t, h.ls.AssignRoleToGroup(ctx, localGroup.ID, role.ID, coreStorage.Scope{}))

	remoteGroup := newGroup("remote")
	require.NoError(t, h.ls.AssignRoleToGroup(ctx, remoteGroup.ID, role.ID, coreStorage.Scope{}))

	localRoles, err := h.ls.GetGroupRoles(ctx, localGroup.ID)
	require.NoError(t, err)
	require.Len(t, localRoles, 1, "sanity: the local group must hold exactly the one assigned role")

	remoteRoles, err := h.rs.GetGroupRoles(ctx, remoteGroup.ID)
	require.NoError(t, err, "RemoteStorage.GetGroupRoles must succeed for a group that genuinely holds a role")
	require.Len(t, remoteRoles, 1,
		"RemoteStorage.GetGroupRoles must return exactly the one role the remote group holds -- a dropped or "+
			"wrong groupID on the wire would return zero or the wrong set")

	// GetGroupRoles' wire response is storage.GroupRoleGrant{ID,Name,Description,ExpiresAt}
	// (server/http/handlers/rbac.go's GetGroupRoles -> core.GetGroupRoleGrants), NOT a full
	// models.Role -- confirmed by direct code read and a live probe. Every field
	// GroupRoleGrant actually carries (ID/Name/Description) has an exact-matching json tag
	// and round-trips with full fidelity into RemoteStorage.GetGroupRoles' []*models.Role
	// unmarshal target; NameFolded (json:"-", never sent) and BypassesPermissionChecks (no
	// such field on GroupRoleGrant at all, so it is simply never set) are excluded.
	exclude := map[string]bool{"NameFolded": true, "BypassesPermissionChecks": true}
	assertFieldExhaustiveEqual(t, "GetGroupRoles(local vs remote, same role)", localRoles[0], remoteRoles[0], exclude)

	// Precondition: LocalStorage.GetGroupRoles has no existence check on groupID (a raw JOIN
	// yielding zero rows for an unmatched group) -- confirmed by direct read of
	// local_rbac.go. core.GetGroupRoleGrants (which the HTTP handler calls) proxies straight
	// to storage.GetGroupRoleGrants, the SAME shape of raw JOIN with no existence check -- so,
	// unlike GetRolePermissions' divergent nonexistent-ID case in tranche 4, both backends
	// genuinely agree here: an empty list, not a 404.
	localEmpty, err := h.ls.GetGroupRoles(ctx, 999999999)
	require.NoError(t, err)
	assert.Empty(t, localEmpty)
	remoteEmpty, err := h.rs.GetGroupRoles(ctx, 999999999)
	require.NoError(t, err,
		"RemoteStorage.GetGroupRoles must not error for a nonexistent groupID -- GetGroupRoleGrants never "+
			"returns not-found, it simply returns an empty slice, matching LocalStorage")
	assert.Empty(t, remoteEmpty)
}
