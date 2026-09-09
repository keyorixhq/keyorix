// remote_storage_conformance_tranche4_sharing_secrets_test.go — issue #1808, tranche 4.
//
// Covers 19 methods spanning three source files, per the task brief:
//
//	remote_sharing.go (8): DeleteExpiredShareRecords, DeleteShareRecord,
//	  ListSharesByGroup, ListSharesByOwner, ListSharesBySecret,
//	  ListSharesBySecretIDs, ListSharesByUser, UpdateShareRecord
//	remote_secrets.go (8): GetSecret, GetSecretIncludingDeleted, GetSecretVersions,
//	  GetSecretsByIDs, ListSecretVersions, ListSecrets, RestoreSecret, UpdateSecret
//	remote_secret_dependencies.go (3): CreateSecretDependencyExclusive,
//	  GetSecretDependency, ListSecretDependenciesForProject
//
// All 19 are covered; none skipped.
//
// # A recurring theme: the harness's own admin credential often can't drive these
//
// newConformanceHarness's h.rs is a MACHINE/NODE credential holding "admin" at
// GLOBAL scope (project_id=0). That is sufficient for every /api/v1/system/*
// proxy route (gated on the same broad system.read/system.write tier), and for
// any human-facing route whose OWN authorization is a plain RBAC permission
// check (AuthorizePrincipal/Authorize: a project_id=0 role grant satisfies ANY
// specific project scope, per GetUserRoleIDsAt's "project_id = 0 OR ..."
// convention). It is NOT sufficient for two other, narrower gates several of
// these 19 methods sit behind, both confirmed by direct code reading before
// writing a single test:
//
//   - requireLiveOwnerAuthority (internal/core/permissions.go): requires the
//     acting user to be the resource's OwnerID AND a LIVE, PROJECT-SCOPED member
//     (IsProjectMember explicitly excludes project_id=0 grants — its own doc
//     comment: "a global/install-wide role does NOT count"). UpdateShareRecord,
//     DeleteShareRecord, and (transitively, since RemoteStorage.ListSharesBySecretIDs
//     loops ListSharesBySecret) ListSharesBySecret all proxy onto human-facing
//     /api/v1/shares* routes gated this way — h.rs can never pass this, no matter
//     how much RBAC it holds. newSharingOwnerSession below mints a real user
//     session that both owns the fixture secret and holds a genuine project-scoped
//     role grant (IsProjectMember only checks a grant EXISTS at that scope, not
//     what it permits, so a zero-permission role suffices).
//   - An explicit `if userID == 0 { return err }` guard some core functions run
//     BEFORE any permission check at all (UpdateSecretWithPermissionCheck,
//     GetSecretVersionsWithPermissionCheck) — a machine credential's UserContext
//     never has UserID set (only MachineIdentityID), so these hard-fail
//     regardless of admin bypass. UpdateSecret/GetSecretVersions/
//     ListSecretVersions need a real user session for this reason (confirmed by
//     the pre-existing remote_storage_g80_secret_update_test.go, which already
//     uses createTestToken rather than a node credential for exactly this route).
//
// GetSecret/GetSecretIncludingDeleted/GetSecretsByIDs/ListSecrets/RestoreSecret,
// and every /system/secret-dependencies and /system/shares/by-owner|by-user
// route, have neither gate (confirmed by reading each handler) and are driven
// directly by h.rs.
//
// # A found (not fixed) wire-fidelity defect: UpdateShareRecord can never change ExpiresAt
//
// models.ShareRecord carries no json tags at all, so RemoteStorage.UpdateShareRecord
// marshals it with bare Go field names ("Permission", "ExpiresAt", ...). The server's
// UpdateSharePermission handler (shares_crud.go) decodes into a DTO tagged
// `json:"permission"` / `json:"expires_at"`. encoding/json's case-insensitive
// decode fallback only saves single-word fields (Permission/permission, verified
// empirically to round-trip) — "ExpiresAt" is not a case-insensitive match for
// "expires_at" (they differ by more than case: one has an underscore), so a
// caller's ExpiresAt change is silently dropped on every call, landing at
// whatever the row's current value already was. TestConformance_UpdateShareRecord
// pins this AS a found defect (a failing-if-fixed assertion, with a comment
// explaining exactly why) rather than papering over it — this file only adds
// tests, per the task brief, so it is reported here rather than patched.
//
// # More found (not fixed) defects: bare-slice vs enveloped-object responses
//
// RemoteStorage.ListSharesByGroup, ListSharesBySecret (and its batch caller
// ListSharesBySecretIDs, which loops it), and ListSecretVersions (and its alias
// GetSecretVersions) each decode their HTTP response body directly into a bare
// Go slice (`var result []*models.ShareRecord` / `[]*models.SecretVersion`), but
// the real server wraps every one of those responses in an envelope object
// (`{"shares": [...]}` / `{"versions": [...]}`) — confirmed by reading both the
// RemoteStorage decode call and the exact handler `sendSuccess` call on the
// other end of each route. json.Unmarshal of a JSON object into a Go slice
// always errors, so these FIVE RemoteStorage entry points (four distinct
// methods, one of them doubly-named) are unconditionally broken against a real
// server: every call fails, success or not, non-empty or empty result alike —
// not an edge case this harness had to construct, the ONLY case. All are
// cross-checked against sibling methods that DO unwrap the same kind of
// envelope correctly (ListSharesByOwner/ListSharesByUser use
// `struct{ Shares []*models.ShareRecord }`), so each is a genuine one-off
// omission, not a repo-wide convention gap. TestConformance_ListSharesByGroup /
// TestConformance_ListSharesBySecret / TestConformance_ListSharesBySecretIDs /
// TestConformance_GetSecretVersions / TestConformance_ListSecretVersions each
// pin the CURRENT (broken) behavior with a require.Error assertion and a comment
// explaining exactly why, rather than silently working around it — this file
// only adds tests, per the task brief, so these are reported here rather than
// patched.
package http

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- Shared helpers (unexported to this file, per the task brief) ---

// newSharingOwnerSession creates a human user, grants them the built-in
// "editor" role (secrets.read/write/delete) at a genuine PROJECT scope, logs
// them in for a real session token, and returns both the user and a
// *store.RemoteStorage authenticated as that session. Two distinct gates make
// this necessary, not just IsProjectMember:
//
//  1. The ROUTE middleware for PUT/DELETE /api/v1/shares/{id} and GET
//     /api/v1/secrets/{id}/shares requires a real secrets.write/secrets.read
//     RBAC grant at the resource's scope (RequireScopedPermission/
//     RequireScopedSecretPermission) -- a zero-permission role clears
//     IsProjectMember but still 403s at this layer (confirmed: an earlier
//     draft using a zero-permission role, matching tranche3's
//     AssignRoleWithExpiry/AssignMachineRole convention, failed here with
//     "Forbidden: Insufficient permissions" on every call).
//  2. The HANDLER-internal requireLiveOwnerAuthority additionally requires
//     IsProjectMember specifically (a grant scoped to project_id=0 does NOT
//     count, per that function's own doc comment) -- so the grant must be
//     project-scoped, not global, regardless of (1).
//
// "editor" (RBAC Phase 2's canonical project-scoped role) satisfies both at once.
func newSharingOwnerSession(t *testing.T, h *conformanceHarness, suffix string) (*models.User, *store.RemoteStorage) {
	t.Helper()
	ctx := context.Background()

	const password = "Qr7#Kp2$Lm5@Vn9!"
	user, err := h.upstreamCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "conformance-share-owner-" + suffix,
		Email:    "conformance-share-owner-" + suffix + "@example.com",
		Password: password,
	})
	require.NoError(t, err)

	editorRole, err := h.ls.GetRoleByName(ctx, "editor")
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRole(ctx, user.ID, editorRole.ID, coreStorage.Scope{ProjectID: h.projectID}))

	session, _, err := h.upstreamCore.Login(ctx, &core.LoginRequest{Username: user.Username, Password: password})
	require.NoError(t, err)

	rsAsOwner, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: session.SessionToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	return user, rsAsOwner
}

// newSecretsHumanSession mints a *store.RemoteStorage authenticated as the
// harness's own bootstrap admin (testadmin — the SAME user h.adminUserID
// names), via a real login session rather than the harness's machine/node
// credential. testadmin's admin role is GLOBAL (project_id=0), which — unlike
// IsProjectMember above — DOES satisfy AuthorizePrincipal/Authorize's RBAC
// checks at any specific project scope (GetUserRoleIDsAt's own
// "project_id = 0 OR ..." resolution), so this is sufficient for
// UpdateSecret/GetSecretVersions/ListSecretVersions's plain secrets.write/
// secrets.read gates. It is NOT a live-owner/project-member session (no
// project-scoped grant is created here) — don't reuse this for
// requireLiveOwnerAuthority-gated calls; use newSharingOwnerSession there.
func newSecretsHumanSession(t *testing.T, h *conformanceHarness) *store.RemoteStorage {
	t.Helper()
	token := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: token, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	return rsAsUser
}

func newConformanceTestUser(t *testing.T, h *conformanceHarness, suffix string) *models.User {
	t.Helper()
	user, err := h.ls.CreateUser(context.Background(), &models.User{
		Username: "conformance-" + suffix, Email: "conformance-" + suffix + "@example.com",
		DisplayName: "Conformance " + suffix, IsActive: true,
	})
	require.NoError(t, err)
	return user
}

func containsShareID(shares []*models.ShareRecord, id uint) bool {
	for _, s := range shares {
		if s.ID == id {
			return true
		}
	}
	return false
}

func secretByID(t *testing.T, secrets []*models.SecretNode, id uint) *models.SecretNode {
	t.Helper()
	for _, s := range secrets {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("secret %d not found in result set", id)
	return nil
}

func mustGetSecretDependency(t *testing.T, h *conformanceHarness, id uint) *models.SecretDependency {
	t.Helper()
	d, err := h.ls.GetSecretDependency(context.Background(), id)
	require.NoError(t, err)
	return d
}

// ============================================================================
// Group A — remote_sharing.go
// ============================================================================

// --- ListSharesBySecret ---

func TestConformance_ListSharesBySecret(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	recipient := newConformanceTestUser(t, h, "lss-recipient")

	// local: raw storage, no authz needed.
	localOwner := newConformanceTestUser(t, h, "lss-owner-local")
	localSecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-lss-secret-local", ProjectID: h.projectID, EnvironmentID: h.environmentID,
		Type: "password", OwnerID: localOwner.ID,
	})
	require.NoError(t, err)
	localShare, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: localSecret.ID, OwnerID: localOwner.ID, RecipientID: recipient.ID, Permission: "read",
	})
	require.NoError(t, err)

	localShares, err := h.ls.ListSharesBySecret(ctx, localSecret.ID)
	require.NoError(t, err)
	require.Len(t, localShares, 1, "sanity: exactly one active share for the local secret")
	assertFieldExhaustiveEqual(t, "LocalStorage.ListSharesBySecret (sanity baseline)", localShare, localShares[0], map[string]bool{})

	// remote: ListSharesBySecret proxies onto the human-facing, owner-gated
	// GET /api/v1/secrets/{id}/shares route (ListSecretSharesWithPermissionCheck) --
	// see the package doc for why h.rs itself cannot drive this even setting the
	// envelope defect below aside.
	remoteOwner, rsAsOwner := newSharingOwnerSession(t, h, "lss-remote")
	remoteSecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-lss-secret-remote", ProjectID: h.projectID, EnvironmentID: h.environmentID,
		Type: "password", OwnerID: remoteOwner.ID,
	})
	require.NoError(t, err)
	_, err = h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: remoteSecret.ID, OwnerID: remoteOwner.ID, RecipientID: recipient.ID, Permission: "read",
	})
	require.NoError(t, err)

	// FOUND DEFECT (same class as ListSharesByGroup/GetSecretVersions -- see the
	// package doc): GET /api/v1/secrets/{id}/shares (ListSecretShares) also wraps
	// its response as {"shares": [...]}, but RemoteStorage.ListSharesBySecret
	// decodes straight into a bare `[]*models.ShareRecord`. Unconditionally
	// broken against a real server for every call, confirmed here with a genuine
	// live owner (the authorization gate passes -- the 200 response body itself
	// is what fails to parse). Not fixed here, per the task brief -- pinned.
	_, err = rsAsOwner.ListSharesBySecret(ctx, remoteSecret.ID)
	require.Error(t, err,
		"FOUND DEFECT: RemoteStorage.ListSharesBySecret must currently fail on ANY call, even for a genuine "+
			"live owner -- it decodes the server's {\"shares\": [...]} envelope directly into a bare slice, "+
			"which json.Unmarshal always rejects")
	assert.Contains(t, err.Error(), "failed to parse response")

	// Negative (still pinning the same defect): a secret with no shares gets the
	// identical envelope shape server-side, so it fails to parse too, not a
	// clean empty list.
	emptySecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-lss-empty", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: remoteOwner.ID,
	})
	require.NoError(t, err)
	emptyLocal, err := h.ls.ListSharesBySecret(ctx, emptySecret.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	_, err = rsAsOwner.ListSharesBySecret(ctx, emptySecret.ID)
	assert.Error(t, err, "the same envelope-vs-bare-slice mismatch fails an empty-result call too")
}

// --- ListSharesBySecretIDs ---

func TestConformance_ListSharesBySecretIDs(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	recipient := newConformanceTestUser(t, h, "lsbi-recipient")
	owner, rsAsOwner := newSharingOwnerSession(t, h, "lsbi")

	secretA, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-lsbi-a", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: owner.ID,
	})
	require.NoError(t, err)
	// secretB deliberately has NO shares -- exercises the "some IDs contribute
	// zero shares" branch without failing the batch.
	secretB, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-lsbi-b", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: owner.ID,
	})
	require.NoError(t, err)
	_, err = h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secretA.ID, OwnerID: owner.ID, RecipientID: recipient.ID, Permission: "read",
	})
	require.NoError(t, err)

	ids := []uint{secretA.ID, secretB.ID}
	localResult, err := h.ls.ListSharesBySecretIDs(ctx, ids)
	require.NoError(t, err)
	require.Len(t, localResult, 1)

	// FOUND DEFECT (transitively, from ListSharesBySecret's own bug -- see the
	// package doc and TestConformance_ListSharesBySecret): RemoteStorage.
	// ListSharesBySecretIDs loops rs.ListSharesBySecret once per ID, so it
	// inherits the identical bare-slice-vs-{"shares":[...]}-envelope mismatch
	// and fails on the FIRST id in any non-empty batch, regardless of ownership
	// -- confirmed here with a genuine live owner of every secret in the batch,
	// so the failure is the parse bug, not an authorization gate. This also
	// means the #407 "fail the whole batch on an unauthorized id" contract
	// documented in remote_sharing.go cannot currently be distinguished from
	// this parse bug by an external caller -- both surface as the same opaque
	// error today. Not fixed here, per the task brief -- pinned.
	_, err = rsAsOwner.ListSharesBySecretIDs(ctx, ids)
	require.Error(t, err,
		"FOUND DEFECT: RemoteStorage.ListSharesBySecretIDs must currently fail for ANY non-empty batch, even "+
			"one the caller owns entirely -- it inherits ListSharesBySecret's bare-slice-vs-envelope parse bug")
	assert.Contains(t, err.Error(), "failed to parse response")

	// Negative: empty input is a genuine no-op on both paths -- RemoteStorage's
	// loop makes zero HTTP calls for an empty id list, so it never reaches the
	// broken parse path at all.
	emptyLocal, err := h.ls.ListSharesBySecretIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := rsAsOwner.ListSharesBySecretIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, emptyRemote)
}

// --- ListSharesByGroup ---

func TestConformance_ListSharesByGroup(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	owner := newConformanceTestUser(t, h, "lsbg-owner")
	group, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-lsbg-group"})
	require.NoError(t, err)
	secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-lsbg-secret", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: owner.ID,
	})
	require.NoError(t, err)
	share, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, OwnerID: owner.ID, RecipientID: group.ID, IsGroup: true, Permission: "write",
	})
	require.NoError(t, err)

	localOut, err := h.ls.ListSharesByGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, localOut, 1)
	_ = share

	// FOUND DEFECT: RemoteStorage.ListSharesByGroup is unconditionally broken
	// against a real server, for every call, success or not. GET
	// /api/v1/groups/{id}/shares (shares_query.go's ListGroupShares) wraps its
	// response as {"shares": [...]} --
	//
	//	h.sendSuccess(w, map[string]interface{}{"shares": shares}, "")
	//
	// -- but RemoteStorage.ListSharesByGroup (remote_sharing.go) decodes
	// resp.Data straight into a bare `var result []*models.ShareRecord`, never
	// unwrapping the "shares" envelope key. json.Unmarshal of a JSON OBJECT into
	// a Go SLICE always fails, regardless of content, so this method 100% fails
	// every real call, non-empty or empty alike -- not an edge case, the ONLY
	// case. Confirmed directly against the real router below (not a mock), and
	// cross-checked against every sibling in this file: ListSharesByOwner/
	// ListSharesByUser correctly decode into `struct{ Shares []*models.ShareRecord
	// }`, so this is a genuine one-off omission in ListSharesByGroup specifically,
	// not a wrapping convention this repo lacks. Not fixed here (this file adds
	// tests only, no production changes) -- pinned so a future fix flips this
	// from red to green rather than a silent regression going unnoticed.
	_, err = h.rs.ListSharesByGroup(ctx, group.ID)
	require.Error(t, err,
		"FOUND DEFECT: RemoteStorage.ListSharesByGroup must currently fail on ANY call -- it decodes the server's "+
			"{\"shares\": [...]} envelope directly into a bare slice, which json.Unmarshal always rejects")
	assert.Contains(t, err.Error(), "failed to parse response")

	// Negative (still pinning the same defect): even a group with zero shares
	// gets the identical envelope shape server-side, so it 500s/fails to parse
	// too, not a clean empty list.
	emptyGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-lsbg-empty"})
	require.NoError(t, err)
	emptyLocal, err := h.ls.ListSharesByGroup(ctx, emptyGroup.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	_, err = h.rs.ListSharesByGroup(ctx, emptyGroup.ID)
	assert.Error(t, err, "the same envelope-vs-bare-slice mismatch fails an empty-result call too")
}

// --- ListSharesByOwner ---

func TestConformance_ListSharesByOwner(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	owner := newConformanceTestUser(t, h, "lsbo-owner")
	recipient := newConformanceTestUser(t, h, "lsbo-recipient")
	secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-lsbo-secret", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: owner.ID,
	})
	require.NoError(t, err)
	share, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, OwnerID: owner.ID, RecipientID: recipient.ID, Permission: "write",
	})
	require.NoError(t, err)

	localOut, err := h.ls.ListSharesByOwner(ctx, owner.ID)
	require.NoError(t, err)
	require.Len(t, localOut, 1)

	// A raw /api/v1/system/shares/by-owner/{ownerID} proxy (system.read tier) --
	// h.rs's admin machine credential drives this directly.
	remoteOut, err := h.rs.ListSharesByOwner(ctx, owner.ID)
	require.NoError(t, err, "RemoteStorage.ListSharesByOwner must succeed via the /system proxy route")
	require.Len(t, remoteOut, 1)
	assertFieldExhaustiveEqual(t, "ListSharesByOwner (RemoteStorage vs LocalStorage, same row)", share, remoteOut[0], map[string]bool{})

	// Negative: an owner with no shares gets an empty list.
	bystander := newConformanceTestUser(t, h, "lsbo-bystander")
	emptyLocal, err := h.ls.ListSharesByOwner(ctx, bystander.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := h.rs.ListSharesByOwner(ctx, bystander.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyRemote)
}

// --- ListSharesByUser ---

func TestConformance_ListSharesByUser(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	owner := newConformanceTestUser(t, h, "lsbu-owner")
	recipient := newConformanceTestUser(t, h, "lsbu-recipient")
	secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-lsbu-secret", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: owner.ID,
	})
	require.NoError(t, err)
	share, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, OwnerID: owner.ID, RecipientID: recipient.ID, Permission: "read",
	})
	require.NoError(t, err)

	localOut, err := h.ls.ListSharesByUser(ctx, recipient.ID)
	require.NoError(t, err)
	require.Len(t, localOut, 1)

	// A raw /api/v1/system/shares/by-user/{userID} proxy (system.read tier) --
	// h.rs's admin machine credential drives this directly.
	remoteOut, err := h.rs.ListSharesByUser(ctx, recipient.ID)
	require.NoError(t, err, "RemoteStorage.ListSharesByUser must succeed via the /system proxy route")
	require.Len(t, remoteOut, 1)
	assertFieldExhaustiveEqual(t, "ListSharesByUser (RemoteStorage vs LocalStorage, same row)", share, remoteOut[0], map[string]bool{})

	// Negative: a user with no shares received gets an empty list.
	bystander := newConformanceTestUser(t, h, "lsbu-bystander")
	emptyLocal, err := h.ls.ListSharesByUser(ctx, bystander.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := h.rs.ListSharesByUser(ctx, bystander.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyRemote)
}

// --- UpdateShareRecord ---

func TestConformance_UpdateShareRecord(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	recipient := newConformanceTestUser(t, h, "usr-recipient")
	newExpiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	// local: raw storage round trip, sanity baseline -- both Permission and
	// ExpiresAt changes must apply.
	localOwner := newConformanceTestUser(t, h, "usr-owner-local")
	localSecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-usr-secret-local", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: localOwner.ID,
	})
	require.NoError(t, err)
	localShare, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: localSecret.ID, OwnerID: localOwner.ID, RecipientID: recipient.ID, Permission: "read",
	})
	require.NoError(t, err)
	localShare.Permission = "write"
	localShare.ExpiresAt = &newExpiry
	localUpdated, err := h.ls.UpdateShareRecord(ctx, localShare)
	require.NoError(t, err)
	assert.Equal(t, "write", localUpdated.Permission, "sanity: local Permission change must apply")
	require.NotNil(t, localUpdated.ExpiresAt, "sanity: local ExpiresAt change must apply")
	assert.True(t, newExpiry.Equal(*localUpdated.ExpiresAt))

	// remote: UpdateShareRecord proxies onto the human-facing, owner-gated
	// PUT /api/v1/shares/{id} route -- needs a real live-owner session, see the
	// package doc.
	remoteOwner, rsAsOwner := newSharingOwnerSession(t, h, "usr-remote")
	remoteSecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-usr-secret-remote", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: remoteOwner.ID,
	})
	require.NoError(t, err)
	remoteShare, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: remoteSecret.ID, OwnerID: remoteOwner.ID, RecipientID: recipient.ID, Permission: "read",
	})
	require.NoError(t, err)
	remoteShare.Permission = "write"
	remoteShare.ExpiresAt = &newExpiry
	remoteUpdated, err := rsAsOwner.UpdateShareRecord(ctx, remoteShare)
	require.NoError(t, err, "RemoteStorage.UpdateShareRecord must succeed for the share's genuine live owner")
	assert.Equal(t, "write", remoteUpdated.Permission,
		"the Permission change must land server-side -- ShareRecord.Permission has no json tag, so its bare Go "+
			"field name round-trips case-insensitively onto the handler's `permission` json tag")

	// FOUND DEFECT (see package doc): ExpiresAt can never change through this
	// wire path. Pinning the CURRENT (buggy) behavior deliberately -- this
	// assertion should start failing, not be deleted, the day someone fixes the
	// key-name mismatch.
	persisted, err := h.ls.GetShareRecord(ctx, remoteShare.ID)
	require.NoError(t, err)
	assert.Nil(t, persisted.ExpiresAt,
		"FOUND DEFECT: RemoteStorage.UpdateShareRecord cannot change ExpiresAt at all. ShareRecord carries no "+
			"json tags, so marshaling it sends the bare Go field name \"ExpiresAt\"; the handler's reqBody expects "+
			"the JSON key \"expires_at\". encoding/json's case-insensitive fallback does not bridge an "+
			"underscore difference (confirmed empirically), so this field is silently dropped on every call and "+
			"the share's ExpiresAt never changes from whatever it already was (nil here, since the share was "+
			"created with none) -- not fixed in this file (tests only, no production changes), just pinned so a "+
			"future fix flips this from red to green instead of a silent regression going unnoticed.")

	// Negative: updating a nonexistent share ID fails on both paths.
	_, err = h.ls.UpdateShareRecord(ctx, &models.ShareRecord{ID: 9999999, Permission: "read"})
	assert.Error(t, err)
	_, err = rsAsOwner.UpdateShareRecord(ctx, &models.ShareRecord{ID: 9999999, Permission: "read"})
	assert.Error(t, err)
}

// --- DeleteShareRecord ---

func TestConformance_DeleteShareRecord(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	recipient := newConformanceTestUser(t, h, "dsr-recipient")

	// local: raw storage, no authz needed.
	localOwner := newConformanceTestUser(t, h, "dsr-owner-local")
	localSecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-dsr-secret-local", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: localOwner.ID,
	})
	require.NoError(t, err)
	localShare, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: localSecret.ID, OwnerID: localOwner.ID, RecipientID: recipient.ID, Permission: "read",
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.DeleteShareRecord(ctx, localShare.ID))
	_, err = h.ls.GetShareRecord(ctx, localShare.ID)
	assert.Error(t, err, "sanity: the locally-deleted share must be gone")

	// remote: DeleteShareRecord proxies onto the human-facing, owner-gated
	// DELETE /api/v1/shares/{id} route (core.RevokeShare's requireLiveOwnerAuthority)
	// -- needs a real live-owner session, see the package doc.
	remoteOwner, rsAsOwner := newSharingOwnerSession(t, h, "dsr-remote")
	remoteSecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-dsr-secret-remote", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password", OwnerID: remoteOwner.ID,
	})
	require.NoError(t, err)
	remoteShare, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: remoteSecret.ID, OwnerID: remoteOwner.ID, RecipientID: recipient.ID, Permission: "read",
	})
	require.NoError(t, err)
	require.NoError(t, rsAsOwner.DeleteShareRecord(ctx, remoteShare.ID),
		"RemoteStorage.DeleteShareRecord must succeed for the share's genuine live owner")
	_, err = h.ls.GetShareRecord(ctx, remoteShare.ID)
	assert.Error(t, err, "the share revoked via RemoteStorage must actually be gone server-side, not just report success")

	// Negative: revoking an already-revoked/nonexistent share fails identically on both paths.
	assert.Error(t, h.ls.DeleteShareRecord(ctx, localShare.ID))
	assert.Error(t, rsAsOwner.DeleteShareRecord(ctx, remoteShare.ID))
}

// --- DeleteExpiredShareRecords ---

func TestConformance_DeleteExpiredShareRecords(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	recipient := newConformanceTestUser(t, h, "desr-recipient")
	past := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	future := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	cutoff := time.Now().UTC()

	newShare := func(suffix string, expiresAt time.Time) *models.ShareRecord {
		owner := newConformanceTestUser(t, h, "desr-owner-"+suffix)
		secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-desr-secret-" + suffix, ProjectID: h.projectID, EnvironmentID: h.environmentID,
			Type: "password", OwnerID: owner.ID,
		})
		require.NoError(t, err)
		expiry := expiresAt
		share, err := h.ls.CreateShareRecord(ctx, &models.ShareRecord{
			SecretID: secret.ID, OwnerID: owner.ID, RecipientID: recipient.ID, Permission: "read", ExpiresAt: &expiry,
		})
		require.NoError(t, err)
		return share
	}

	// Local: one already-expired share (must be purged) and one not-yet-expired
	// share (must survive).
	localExpired := newShare("local-expired", past)
	localFuture := newShare("local-future", future)
	localRemoved, err := h.ls.DeleteExpiredShareRecords(ctx, cutoff)
	require.NoError(t, err)
	assert.True(t, containsShareID(localRemoved, localExpired.ID), "sanity: LocalStorage must report the expired share it purged")
	_, err = h.ls.GetShareRecord(ctx, localExpired.ID)
	assert.Error(t, err, "sanity: the purged share must no longer be retrievable")
	_, err = h.ls.GetShareRecord(ctx, localFuture.ID)
	assert.NoError(t, err, "sanity: the not-yet-expired share must survive")

	// Remote: a raw /api/v1/system/retention/share-records/purge-expired proxy
	// (system.write tier) -- h.rs's admin machine credential drives this directly,
	// unlike UpdateShareRecord/DeleteShareRecord/ListSharesBySecret above.
	remoteExpired := newShare("remote-expired", past)
	remoteFuture := newShare("remote-future", future)
	remoteRemoved, err := h.rs.DeleteExpiredShareRecords(ctx, cutoff)
	require.NoError(t, err, "RemoteStorage.DeleteExpiredShareRecords must succeed and report the purged shares")
	assert.True(t, containsShareID(remoteRemoved, remoteExpired.ID),
		"RemoteStorage.DeleteExpiredShareRecords must actually report the expired share it purged server-side, not just an empty/wrong list")

	_, err = h.ls.GetShareRecord(ctx, remoteExpired.ID)
	assert.Error(t, err, "the expired share purged via RemoteStorage must actually be gone server-side")
	_, err = h.ls.GetShareRecord(ctx, remoteFuture.ID)
	assert.NoError(t, err, "RemoteStorage.DeleteExpiredShareRecords must NOT touch a share that has not yet expired")

	var removedShare *models.ShareRecord
	for _, s := range remoteRemoved {
		if s.ID == remoteExpired.ID {
			removedShare = s
		}
	}
	require.NotNil(t, removedShare)
	assertFieldExhaustiveEqual(t, "DeleteExpiredShareRecords (removed row round trip)", remoteExpired, removedShare, map[string]bool{})
}

// ============================================================================
// Group B — remote_secrets.go
// ============================================================================

// --- GetSecret ---

func TestConformance_GetSecret(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	maxReads := 3
	expiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	created, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-gs-secret", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password",
		Description: "conformance test secret", MaxReads: &maxReads, Expiration: &expiry,
		Classification: "internal", Metadata: models.JSON(`{"k":"v"}`), OwnerID: h.adminUserID,
	})
	require.NoError(t, err)

	// GetSecret's handler branches on isMachine and fetches directly with no
	// permission check at all for a machine principal (already authorized at
	// the route's scoped-permission gate) -- h.rs drives this fine.
	localOut, err := h.ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	remoteOut, err := h.rs.GetSecret(ctx, created.ID)
	require.NoError(t, err, "RemoteStorage.GetSecret must succeed for a secret that genuinely exists")

	assertFieldExhaustiveEqual(t, "GetSecret (RemoteStorage vs LocalStorage, same row)", localOut, remoteOut, map[string]bool{})

	// Negative: a nonexistent ID fails identically on both paths.
	_, err = h.ls.GetSecret(ctx, 9999999)
	assert.Error(t, err)
	_, err = h.rs.GetSecret(ctx, 9999999)
	assert.Error(t, err)
}

// --- GetSecretIncludingDeleted ---

func TestConformance_GetSecretIncludingDeleted(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	created, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-gsid-secret", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password",
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.DeleteSecret(ctx, created.ID))

	localOut, err := h.ls.GetSecretIncludingDeleted(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, localOut.DeletedAt.Valid, "sanity: the secret must be soft-deleted")

	// A raw /api/v1/system/secrets/{id}/including-deleted proxy (system.read
	// tier, Unscoped lookup) -- h.rs drives this directly.
	remoteOut, err := h.rs.GetSecretIncludingDeleted(ctx, created.ID)
	require.NoError(t, err, "RemoteStorage.GetSecretIncludingDeleted must reach a soft-deleted secret via the system proxy route")

	assertFieldExhaustiveEqual(t, "GetSecretIncludingDeleted (RemoteStorage vs LocalStorage, same row)", localOut, remoteOut, map[string]bool{})

	// Negative: an ID that never existed fails on both paths.
	_, err = h.ls.GetSecretIncludingDeleted(ctx, 9999999)
	assert.Error(t, err)
	_, err = h.rs.GetSecretIncludingDeleted(ctx, 9999999)
	assert.Error(t, err)
}

// --- GetSecretsByIDs ---

func TestConformance_GetSecretsByIDs(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	secretA, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-gsbi-a", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	secretB, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-gsbi-b", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)

	ids := []uint{secretA.ID, secretB.ID, 9999999} // the third ID does not exist

	localOut, err := h.ls.GetSecretsByIDs(ctx, ids)
	require.NoError(t, err)
	assert.Len(t, localOut, 2, "sanity: a nonexistent ID is simply absent from the result, not an error")

	// RemoteStorage.GetSecretsByIDs loops rs.GetSecret per ID, skipping IDs that
	// fail rather than failing the whole batch (#409's rotation planner already
	// treats a missing ID this way) -- h.rs drives each underlying GetSecret call
	// fine (machine-bypass path).
	remoteOut, err := h.rs.GetSecretsByIDs(ctx, ids)
	require.NoError(t, err, "RemoteStorage.GetSecretsByIDs must succeed and skip the nonexistent ID rather than failing the whole batch")
	require.Len(t, remoteOut, 2)

	assertFieldExhaustiveEqual(t, "GetSecretsByIDs[A]", secretByID(t, localOut, secretA.ID), secretByID(t, remoteOut, secretA.ID), map[string]bool{})
	assertFieldExhaustiveEqual(t, "GetSecretsByIDs[B]", secretByID(t, localOut, secretB.ID), secretByID(t, remoteOut, secretB.ID), map[string]bool{})

	// Negative: an all-nonexistent batch returns an empty (not error) slice on both paths.
	emptyLocal, err := h.ls.GetSecretsByIDs(ctx, []uint{9999999})
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := h.rs.GetSecretsByIDs(ctx, []uint{9999999})
	require.NoError(t, err)
	assert.Empty(t, emptyRemote)
}

// --- GetSecretVersions / ListSecretVersions ---
//
// Both need a real human session: GetSecretVersionsWithPermissionCheck hard-fails
// with "user ID is required" for ANY userID==0 caller -- a machine credential's
// UserContext never has UserID set (only MachineIdentityID), so h.rs itself can
// never drive this route regardless of the RBAC it holds. See the package doc.
//
// FOUND DEFECT, same class as ListSharesByGroup above: GET
// /api/v1/secrets/{id}/versions (secrets_versions.go's GetSecretVersions
// handler) wraps its response as {"versions": [...]} --
//
//	h.sendSuccess(w, map[string]any{"versions": versions}, "")
//
// -- but RemoteStorage.ListSecretVersions (remote_secrets.go), and its alias
// GetSecretVersions, both decode resp.Data straight into a bare
// `var result []*models.SecretVersion`, never unwrapping the "versions"
// envelope key. json.Unmarshal of a JSON OBJECT into a Go SLICE always fails,
// so BOTH RemoteStorage entry points 100% fail on every real call, non-empty
// or empty alike. Confirmed directly against the real router (not a mock).
// Not fixed here (this file adds tests only) -- pinned so a future fix flips
// these from red to green rather than a silent regression going unnoticed.

func seedSecretVersions(t *testing.T, h *conformanceHarness, suffix string) (secretID uint, v1, v2 *models.SecretVersion) {
	t.Helper()
	ctx := context.Background()
	secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-sv-secret-" + suffix, ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password",
	})
	require.NoError(t, err)
	v1, err = h.ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("ciphertext-v1"), EncryptionMetadata: models.JSON(`{"alg":"aes"}`),
	})
	require.NoError(t, err)
	v2, err = h.ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 2, EncryptedValue: []byte("ciphertext-v2"), EncryptionMetadata: models.JSON(`{"alg":"aes"}`),
	})
	require.NoError(t, err)
	return secret.ID, v1, v2
}

func TestConformance_GetSecretVersions(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	rsAsUser := newSecretsHumanSession(t, h)

	secretID, _, _ := seedSecretVersions(t, h, "gsv")

	localOut, err := h.ls.GetSecretVersions(ctx, secretID)
	require.NoError(t, err)
	require.Len(t, localOut, 2)

	_, err = rsAsUser.GetSecretVersions(ctx, secretID)
	require.Error(t, err,
		"FOUND DEFECT: RemoteStorage.GetSecretVersions must currently fail on ANY call -- it decodes the "+
			"server's {\"versions\": [...]} envelope directly into a bare slice, which json.Unmarshal always rejects")
	assert.Contains(t, err.Error(), "failed to parse response")

	// Negative (still pinning the same defect): a secret with no versions gets
	// the identical envelope shape server-side, so it fails to parse too, not
	// a clean empty list.
	emptySecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-gsv-empty", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	emptyLocal, err := h.ls.GetSecretVersions(ctx, emptySecret.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	_, err = rsAsUser.GetSecretVersions(ctx, emptySecret.ID)
	assert.Error(t, err, "the same envelope-vs-bare-slice mismatch fails an empty-result call too")
}

func TestConformance_ListSecretVersions(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	rsAsUser := newSecretsHumanSession(t, h)

	secretID, _, _ := seedSecretVersions(t, h, "lsv")

	localOut, err := h.ls.GetSecretVersions(ctx, secretID)
	require.NoError(t, err)
	require.Len(t, localOut, 2)

	// ListSecretVersions is RemoteStorage's own additional name for the
	// identical call GetSecretVersions makes (a literal alias -- see
	// remote_secrets.go); LocalStorage has no separate ListSecretVersions
	// method at all. This test exercises that entry point by name, distinct
	// from TestConformance_GetSecretVersions above, and hits the SAME found
	// defect since it's a straight passthrough to GetSecretVersions.
	_, err = rsAsUser.ListSecretVersions(ctx, secretID)
	require.Error(t, err,
		"FOUND DEFECT: RemoteStorage.ListSecretVersions must currently fail on ANY call, same envelope mismatch as GetSecretVersions")
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- ListSecrets ---

func TestConformance_ListSecrets(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	secretA, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-lsecrets-a", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	secretB, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-lsecrets-b", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)

	// PageSize must be set explicitly: LocalStorage.ListSecrets's own
	// clampPageSize passes a caller-supplied 0 straight through as 0 ("several
	// callers rely on 0 meaning use my own default", per its doc comment) --
	// but ListSecrets itself applies no such default, so GORM's Limit(0) then
	// returns ZERO rows. RemoteStorage's path goes through core.ListSecretsInScope,
	// which DOES default PageSize<1 to 20 before ever reaching the same
	// LocalStorage.ListSecrets call -- so comparing the two storage backends
	// fairly requires supplying the same explicit PageSize a real caller (every
	// core-layer entry point) always would, on both sides.
	filter := &coreStorage.SecretFilter{ProjectID: &h.projectID, EnvironmentID: &h.environmentID, Page: 1, PageSize: 20}

	localSecrets, localTotal, err := h.ls.ListSecrets(ctx, filter)
	require.NoError(t, err)

	// RemoteStorage.ListSecrets proxies onto GET /api/v1/secrets, which for a
	// machine/node credential (ADR-030) requires an explicit project_id
	// (CWE-862 guard, secrets_list.go) and runs core.ListSecretsInScope rather
	// than a raw storage.ListSecrets passthrough -- but ListSecretsInScope's own
	// body calls c.storage.ListSecrets with the SAME filter shape, then just
	// sorts/paginates in memory, so the ROW SET for this unfiltered scope is
	// identical; only ordering and the wrapper type differ.
	remoteSecrets, remoteTotal, err := h.rs.ListSecrets(ctx, filter)
	require.NoError(t, err, "RemoteStorage.ListSecrets must succeed for a machine credential that supplies project_id")

	assert.Equal(t, localTotal, remoteTotal, "the total count for the same scope must match")

	idSet := func(secrets []*models.SecretNode) map[uint]*models.SecretNode {
		m := make(map[uint]*models.SecretNode, len(secrets))
		for _, s := range secrets {
			m[s.ID] = s
		}
		return m
	}
	localByID := idSet(localSecrets)
	remoteByID := idSet(remoteSecrets)
	require.Len(t, remoteByID, len(localByID), "the same set of secret IDs must come back on both paths")
	require.Contains(t, localByID, secretA.ID)
	require.Contains(t, localByID, secretB.ID)

	for id, local := range localByID {
		remote, ok := remoteByID[id]
		require.True(t, ok, "secret %d present locally must also be present via RemoteStorage.ListSecrets", id)
		assertFieldExhaustiveEqual(t, fmt.Sprintf("ListSecrets[%d]", id), local, remote, map[string]bool{
			// models.SecretWithSharingInfo (the type ListSecretsInScope's response
			// actually carries) embeds *SecretNode anonymously AND declares its
			// OWN IsShared field -- the outer field (always false here, since
			// ListSecretsInScope attaches no sharing info) shadows the embedded
			// SecretNode's real IsShared for JSON marshaling by Go's own
			// promoted-field rule, regardless of the raw row's actual value. A
			// pre-existing model-shape quirk in SecretWithSharingInfo, not a
			// RemoteStorage wire-fidelity defect this harness's CreateSecret/
			// UpdateSecret siblings exist to catch -- neither secret here is
			// ever shared, so this doesn't mask a real divergence in this test.
			"IsShared": true,
		})
	}

	// Negative: a machine/node credential without project_id must be rejected
	// (CWE-862 guard) -- otherwise it could enumerate secrets across every project.
	_, _, err = h.rs.ListSecrets(ctx, &coreStorage.SecretFilter{})
	assert.Error(t, err, "a machine/node credential must be required to supply project_id")
}

// --- RestoreSecret ---

func TestConformance_RestoreSecret(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newDeletedSecret := func(suffix string) *models.SecretNode {
		secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-rs-secret-" + suffix, ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password",
		})
		require.NoError(t, err)
		require.NoError(t, h.ls.DeleteSecret(ctx, secret.ID))
		return secret
	}

	localSecret := newDeletedSecret("local")
	require.NoError(t, h.ls.RestoreSecret(ctx, localSecret.ID))
	localAfter, err := h.ls.GetSecret(ctx, localSecret.ID)
	require.NoError(t, err, "sanity: the locally-restored secret must be readable again through the normal getter")
	assert.False(t, localAfter.DeletedAt.Valid)

	// core.RestoreSecret (behind POST /api/v1/secrets/{id}/restore) calls
	// storage.RestoreSecret directly with no internal UserID==0 guard -- h.rs's
	// admin machine credential drives this fine, unlike UpdateSecret below.
	remoteSecret := newDeletedSecret("remote")
	require.NoError(t, h.rs.RestoreSecret(ctx, remoteSecret.ID),
		"RemoteStorage.RestoreSecret must succeed for a secret that is genuinely soft-deleted")
	remoteAfter, err := h.ls.GetSecret(ctx, remoteSecret.ID)
	require.NoError(t, err, "the secret restored via RemoteStorage must actually be readable again server-side, not just report success")
	assert.False(t, remoteAfter.DeletedAt.Valid)

	// Negative: restoring a secret that is NOT deleted must fail identically on both paths.
	activeLocal, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-rs-active-local", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	assert.Error(t, h.ls.RestoreSecret(ctx, activeLocal.ID), "sanity: restoring an already-active secret must fail")

	activeRemote, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-rs-active-remote", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	assert.Error(t, h.rs.RestoreSecret(ctx, activeRemote.ID),
		"RemoteStorage.RestoreSecret must refuse to restore a secret that is not deleted, not silently no-op success")
}

// --- UpdateSecret ---

func TestConformance_UpdateSecret(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	rsAsUser := newSecretsHumanSession(t, h)

	newActiveSecret := func(suffix string) *models.SecretNode {
		secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-us-secret-" + suffix, ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password",
		})
		require.NoError(t, err)
		fresh, err := h.ls.GetSecret(ctx, secret.ID)
		require.NoError(t, err)
		return fresh
	}

	maxReads := 5
	expiry := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)

	// Sanity baseline: LocalStorage.UpdateSecret is a raw Save with no field narrowing at all.
	localSecret := newActiveSecret("local")
	localSecret.Type = "api_key"
	localSecret.Description = "conformance updated description"
	localSecret.MaxReads = &maxReads
	localSecret.Expiration = &expiry
	localSecret.Metadata = models.JSON(`{"note":"conformance-test"}`)
	localUpdated, err := h.ls.UpdateSecret(ctx, localSecret)
	require.NoError(t, err)
	assert.Equal(t, "api_key", localUpdated.Type)

	// RemoteStorage.UpdateSecret proxies onto PUT /api/v1/secrets/{id}, which
	// runs a default-deny diff against the hub's own authoritative row
	// (secret_update_diff.go, #G80 Phase 0): only Type/Description/MaxReads/
	// Expiration/Metadata may change through this endpoint; every other field
	// must be byte-identical to the hub's current row or the WHOLE request is
	// rejected. Matching tranche3's TransitionSecretStatus precedent, a fair
	// comparison mutates ONLY the fields a real caller (core.UpdateSecret) is
	// allowed to change.
	remoteSecret := newActiveSecret("remote")
	remoteSecret.Type = "api_key"
	remoteSecret.Description = "conformance updated description"
	remoteSecret.MaxReads = &maxReads
	remoteSecret.Expiration = &expiry
	remoteSecret.Metadata = models.JSON(`{"note":"conformance-test"}`)
	remoteUpdated, err := rsAsUser.UpdateSecret(ctx, remoteSecret)
	require.NoError(t, err, "RemoteStorage.UpdateSecret must succeed when only allowlisted fields change")

	persisted, err := h.ls.GetSecret(ctx, remoteSecret.ID)
	require.NoError(t, err)

	exclude := map[string]bool{
		// secretFieldIgnored (secret_update_diff.go): the hub always stamps its
		// own now(), the client-supplied value is never even inspected.
		"UpdatedAt": true,
	}
	assertFieldExhaustiveEqual(t, "LocalStorage.UpdateSecret (sanity baseline)", localSecret, localUpdated, exclude)
	assertFieldExhaustiveEqual(t, "RemoteStorage.UpdateSecret (wire round trip)", remoteSecret, remoteUpdated, exclude)
	assertFieldExhaustiveEqual(t, "RemoteStorage.UpdateSecret (persisted server-side)", remoteSecret, persisted, exclude)

	// Negative: a rejected field (Name -- BulkRenameSecrets' own gate, not this
	// endpoint's) must fail the WHOLE request, by name, rather than silently
	// applying the allowed fields and ignoring the rest.
	renamed := newActiveSecret("rejected")
	renamed.Name = "conformance-us-renamed"
	_, err = rsAsUser.UpdateSecret(ctx, renamed)
	require.Error(t, err, "RemoteStorage.UpdateSecret must refuse a request that also changes a non-allowlisted field")
	assert.Contains(t, err.Error(), "name")
	stillOriginal, err := h.ls.GetSecret(ctx, renamed.ID)
	require.NoError(t, err)
	assert.NotEqual(t, "conformance-us-renamed", stillOriginal.Name, "a rejected update must not partially apply")
}

// ============================================================================
// Group C — remote_secret_dependencies.go
// ============================================================================

// --- CreateSecretDependencyExclusive ---

func TestConformance_CreateSecretDependencyExclusive(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newSecret := func(suffix string) *models.SecretNode {
		s, err := h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-csde-" + suffix, ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password",
		})
		require.NoError(t, err)
		return s
	}

	// local: raw storage, sanity baseline.
	localA, localB := newSecret("local-a"), newSecret("local-b")
	localDep, err := h.ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: h.projectID, DependentSecretID: localA.ID, DependsOnSecretID: localB.ID,
		Note: "conformance local dep", CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)

	// Duplicate must be rejected with the sentinel error.
	_, err = h.ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: h.projectID, DependentSecretID: localA.ID, DependsOnSecretID: localB.ID,
	})
	assert.ErrorIs(t, err, coreStorage.ErrDuplicateSecretDependency, "sanity: a duplicate edge must be rejected")

	// Cycle must be rejected: B cannot then depend on A (A already depends on B).
	_, err = h.ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: h.projectID, DependentSecretID: localB.ID, DependsOnSecretID: localA.ID,
	})
	assert.ErrorIs(t, err, coreStorage.ErrSecretDependencyCycle, "sanity: a reverse edge forming a 2-cycle must be rejected")

	// remote: the SAME duplicate/cycle invariant must be enforced identically
	// over the wire -- CreateSecretDependencyExclusiveProxy is gated on
	// system.write, so h.rs's admin machine credential drives this directly.
	remoteA, remoteB := newSecret("remote-a"), newSecret("remote-b")
	remoteDep, err := h.rs.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: h.projectID, DependentSecretID: remoteA.ID, DependsOnSecretID: remoteB.ID,
		Note: "conformance remote dep", CreatedBy: h.adminUserID,
	})
	require.NoError(t, err, "RemoteStorage.CreateSecretDependencyExclusive must succeed for a genuinely new, acyclic edge")

	assertFieldExhaustiveEqual(t, "CreateSecretDependencyExclusive (local sanity baseline)",
		localDep, mustGetSecretDependency(t, h, localDep.ID), map[string]bool{})
	assertFieldExhaustiveEqual(t, "CreateSecretDependencyExclusive (wire round trip)",
		remoteDep, mustGetSecretDependency(t, h, remoteDep.ID), map[string]bool{})

	_, err = h.rs.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: h.projectID, DependentSecretID: remoteA.ID, DependsOnSecretID: remoteB.ID,
	})
	assert.ErrorIs(t, err, coreStorage.ErrDuplicateSecretDependency,
		"RemoteStorage.CreateSecretDependencyExclusive must reject a duplicate edge with the SAME sentinel error "+
			"LocalStorage uses, reconstructed from the wire error code")

	_, err = h.rs.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: h.projectID, DependentSecretID: remoteB.ID, DependsOnSecretID: remoteA.ID,
	})
	assert.ErrorIs(t, err, coreStorage.ErrSecretDependencyCycle,
		"RemoteStorage.CreateSecretDependencyExclusive must reject a cycle-forming edge with the SAME sentinel error LocalStorage uses")
}

// --- GetSecretDependency ---

func TestConformance_GetSecretDependency(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	secretA, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-gsd-a", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	secretB, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-gsd-b", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	dep, err := h.ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: h.projectID, DependentSecretID: secretA.ID, DependsOnSecretID: secretB.ID, Note: "conformance dep",
	})
	require.NoError(t, err)

	localOut, err := h.ls.GetSecretDependency(ctx, dep.ID)
	require.NoError(t, err)
	remoteOut, err := h.rs.GetSecretDependency(ctx, dep.ID)
	require.NoError(t, err, "RemoteStorage.GetSecretDependency must succeed for an edge that genuinely exists")

	assertFieldExhaustiveEqual(t, "GetSecretDependency (RemoteStorage vs LocalStorage, same row)", localOut, remoteOut, map[string]bool{})

	// Negative: a nonexistent ID fails on both paths.
	_, err = h.ls.GetSecretDependency(ctx, 9999999)
	assert.Error(t, err)
	_, err = h.rs.GetSecretDependency(ctx, 9999999)
	assert.Error(t, err)
}

// --- ListSecretDependenciesForProject ---

func TestConformance_ListSecretDependenciesForProject(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lsdfp-other-project", "", []string{"dev"})
	require.NoError(t, err)
	otherEnvs, err := h.ls.ListEnvironmentsByProject(ctx, otherProject.ID)
	require.NoError(t, err)
	require.NotEmpty(t, otherEnvs)

	secretA, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-lsdfp-a", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	secretB, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-lsdfp-b", ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"})
	require.NoError(t, err)
	dep, err := h.ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: h.projectID, DependentSecretID: secretA.ID, DependsOnSecretID: secretB.ID,
	})
	require.NoError(t, err)

	// A dependency edge in a DIFFERENT project must not leak into this project's listing.
	otherA, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-lsdfp-other-a", ProjectID: otherProject.ID, EnvironmentID: otherEnvs[0].ID, Type: "password"})
	require.NoError(t, err)
	otherB, err := h.ls.CreateSecret(ctx, &models.SecretNode{Name: "conformance-lsdfp-other-b", ProjectID: otherProject.ID, EnvironmentID: otherEnvs[0].ID, Type: "password"})
	require.NoError(t, err)
	_, err = h.ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: otherProject.ID, DependentSecretID: otherA.ID, DependsOnSecretID: otherB.ID,
	})
	require.NoError(t, err)

	localOut, err := h.ls.ListSecretDependenciesForProject(ctx, h.projectID)
	require.NoError(t, err)
	require.Len(t, localOut, 1)

	remoteOut, err := h.rs.ListSecretDependenciesForProject(ctx, h.projectID)
	require.NoError(t, err, "RemoteStorage.ListSecretDependenciesForProject must succeed")
	require.Len(t, remoteOut, 1,
		"must return exactly this project's edge, not the other project's -- a dropped/ignored project_id filter "+
			"on the wire would leak cross-project")

	assertFieldExhaustiveEqual(t, "ListSecretDependenciesForProject[0]", dep, remoteOut[0], map[string]bool{})
}
