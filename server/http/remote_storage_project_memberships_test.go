package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForMemberships builds the standard #452/#507/#511
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers (including the new /api/v1/system/project-memberships
// routes, server/http/handlers/project_memberships_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage. Mirrors
// newUpstreamDownstreamForInvitations exactly.
func newUpstreamDownstreamForMemberships(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore, projectID uint, baseURL string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createNodeToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)

	ctx := context.Background()
	project, err := upstream.CreateProject(ctx, "Memberships Test Project", "")
	require.NoError(t, err)
	return upstream, downstream, project.ID, upstreamSrv.URL
}

// buildInvitedMembership mirrors what internal/core/membership_lifecycle.go's
// inviteMemberWithMode computes before calling storage.CreateProjectMembership —
// a freshly invited (allowlist-mode) membership row — WITHOUT going through
// InviteMember/inviteMemberWithMode itself (that path also needs
// storage.GetRoleByName, whose RemoteStorage implementation targets an
// unregistered route — #512, a separate, pre-existing "implemented client
// method, missing server route" bug independent of #511, exactly the same class
// remote_storage_invitations_test.go's buildPendingInvitation already documents
// working around for InviteToProject).
func buildInvitedMembership(now time.Time, projectID, userID uint, role string, invitedBy uint) *models.ProjectMembership {
	return &models.ProjectMembership{
		ProjectID: projectID,
		UserID:    userID,
		Role:      role,
		State:     core.MembershipInvited,
		InvitedBy: invitedBy,
		InvitedAt: now,
		UpdatedAt: now,
	}
}

func mustCreateUser(t *testing.T, c *core.KeyorixCore, username, email string) uint {
	t.Helper()
	u, err := c.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: username, Email: email, Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	return u.ID
}

// TestRemoteStorageMembership_CreateGetList_RealServer proves the #511 fix for
// CreateProjectMembership/GetProjectMembership/ListProjectMemberships: a
// membership is genuinely persisted on the upstream server via the DOWNSTREAM's
// RemoteStorage, fetchable by ID, and listed — all via storage.type: remote
// against a real router, not a protocol mock.
func TestRemoteStorageMembership_CreateGetList_RealServer(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	now := time.Now()
	userID := mustCreateUser(t, upstream, "invitee1", "invitee1@example.com")

	m, err := downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, userID, "viewer", 1))
	require.NoError(t, err, "creating a membership must succeed via storage.type: remote")
	require.NotZero(t, m.ID, "the upstream must assign a real ID")
	assert.Equal(t, projectID, m.ProjectID)
	assert.Equal(t, userID, m.UserID)
	assert.Equal(t, "viewer", m.Role)
	assert.Equal(t, core.MembershipInvited, m.State)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, userID, direct.UserID)

	// GetProjectMembership via the downstream (RemoteStorage) round-trips every
	// field correctly.
	fetched, err := downstream.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, m.ID, fetched.ID)
	assert.Equal(t, m.ProjectID, fetched.ProjectID)
	assert.Equal(t, m.UserID, fetched.UserID)
	assert.Equal(t, m.Role, fetched.Role)
	assert.Equal(t, m.State, fetched.State)
	assert.WithinDuration(t, m.InvitedAt, fetched.InvitedAt, time.Second)

	// A second membership for a different user, then list both back via the
	// downstream's ListProjectMemberships.
	userID2 := mustCreateUser(t, upstream, "invitee2", "invitee2@example.com")
	_, err = downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, userID2, "viewer", 1))
	require.NoError(t, err)

	rows, err := downstream.Storage().ListProjectMemberships(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	users := map[uint]bool{}
	for _, r := range rows {
		users[r.UserID] = true
	}
	assert.True(t, users[userID])
	assert.True(t, users[userID2])
}

// TestRemoteStorageMembership_GetNotFound_RealServer proves a clean not-found
// error (not a panic, not a garbage 500) for a nonexistent membership ID.
func TestRemoteStorageMembership_GetNotFound_RealServer(t *testing.T) {
	_, downstream, _, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetProjectMembership(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageMembership_Update_RealServer proves UpdateProjectMembership
// round-trips a state transition over the real HTTP hop — a single passthrough
// PUT onto local_memberships.go's plain Save (see remote_memberships.go's package
// doc for why no conditional-write guarantee is needed here, unlike
// UpdateProjectInvitation).
func TestRemoteStorageMembership_Update_RealServer(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	now := time.Now()
	userID := mustCreateUser(t, upstream, "activatee", "activatee@example.com")

	m, err := downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, userID, "viewer", 1))
	require.NoError(t, err)

	activatedAt := time.Now()
	m.State = core.MembershipActive
	m.ActivatedAt = &activatedAt
	err = downstream.Storage().UpdateProjectMembership(ctx, m)
	require.NoError(t, err)

	fetched, err := downstream.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipActive, fetched.State)
	require.NotNil(t, fetched.ActivatedAt)
	assert.WithinDuration(t, activatedAt, *fetched.ActivatedAt, time.Second)

	// Directly against the upstream's own storage too, proving this isn't an
	// artifact of RemoteStorage's response cache.
	direct, err := upstream.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipActive, direct.State)
}

// TestRemoteStorageMembership_GetActive_RealServer proves GetActiveProjectMembership
// — the read inviteMemberWithMode uses to reject a duplicate onboarding (#309) —
// finds a non-revoked row and stops finding it once revoked.
func TestRemoteStorageMembership_GetActive_RealServer(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	now := time.Now()
	userID := mustCreateUser(t, upstream, "activeuser", "activeuser@example.com")

	m, err := downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, userID, "viewer", 1))
	require.NoError(t, err)

	active, err := downstream.Storage().GetActiveProjectMembership(ctx, projectID, userID)
	require.NoError(t, err)
	assert.Equal(t, m.ID, active.ID)

	// Revoke it through the SAME downstream RemoteStorage client (not directly
	// against upstream): RemoteStorage's GET response cache is keyed by path with
	// a 5-minute TTL and is only invalidated by a write THROUGH THIS SAME client
	// instance (internal/storage/remote/client.go's Request) — an out-of-band
	// write via a different client/instance wouldn't invalidate it, which is a
	// pre-existing, documented characteristic of the cache (see remote_users.go's
	// LockUserForUpdate comment), not something this test is trying to exercise.
	revokedAt := time.Now()
	m.State = core.MembershipRevoked
	m.RevokedAt = &revokedAt
	require.NoError(t, downstream.Storage().UpdateProjectMembership(ctx, m))

	_, err = downstream.Storage().GetActiveProjectMembership(ctx, projectID, userID)
	assert.Error(t, err, "a revoked membership must not be reported as active")
}

// TestRemoteStorageMembership_DuplicateActiveMembership_RealServer proves the
// #309 DB-level partial unique index (uniq_project_memberships_active) is still
// enforced across the HTTP hop, AND that CreateMembershipProxy translates the
// resulting unique-constraint violation into the SAME storage.ErrDuplicateActiveMembership
// sentinel inviteMemberWithMode's errors.Is check depends on — not an opaque,
// unclassifiable storage error.
func TestRemoteStorageMembership_DuplicateActiveMembership_RealServer(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	now := time.Now()
	userID := mustCreateUser(t, upstream, "dupuser", "dupuser@example.com")

	_, err := downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, userID, "viewer", 1))
	require.NoError(t, err)

	// A second, concurrent-in-spirit invite for the SAME (project, user) pair must
	// be rejected by the upstream's real DB-level unique index, and the rejection
	// must reconstruct as storage.ErrDuplicateActiveMembership on this side of the
	// HTTP hop.
	_, err = downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, userID, "editor", 1))
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrDuplicateActiveMembership),
		"a duplicate active membership must surface as storage.ErrDuplicateActiveMembership, not an opaque error: %v", err)
}

// TestRemoteStorageMembership_ListStaleInvited_RealServer proves
// ListStaleInvitedMemberships (ADR-022 stale-invite warnings) round-trips over
// storage.type: remote.
func TestRemoteStorageMembership_ListStaleInvited_RealServer(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	old := time.Now().Add(-10 * 24 * time.Hour)
	fresh := time.Now()
	staleUserID := mustCreateUser(t, upstream, "staleuser", "staleuser@example.com")
	freshUserID := mustCreateUser(t, upstream, "freshuser", "freshuser@example.com")

	_, err := downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(old, projectID, staleUserID, "viewer", 1))
	require.NoError(t, err)
	_, err = downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(fresh, projectID, freshUserID, "viewer", 1))
	require.NoError(t, err)

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	stale, err := downstream.Storage().ListStaleInvitedMemberships(ctx, cutoff)
	require.NoError(t, err)
	found := false
	for _, m := range stale {
		if m.UserID == staleUserID {
			found = true
		}
		assert.NotEqual(t, freshUserID, m.UserID, "a fresh invite must not be reported as stale")
	}
	assert.True(t, found, "the old invite must be reported as stale")
}

// TestRemoteStorageMembership_ListByUserAndCounts_RealServer proves
// ListUserProjectMemberships and CountProjectMembershipsByUsers (ADR-025 per-user
// assignments/user-list views) round-trip over storage.type: remote.
func TestRemoteStorageMembership_ListByUserAndCounts_RealServer(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	now := time.Now()
	userID := mustCreateUser(t, upstream, "multiuser", "multiuser@example.com")
	otherUserID := mustCreateUser(t, upstream, "otheruser", "otheruser@example.com")

	project2, err := upstream.CreateProject(ctx, "Second Project", "")
	require.NoError(t, err)

	m1, err := downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, userID, "viewer", 1))
	require.NoError(t, err)
	activatedAt := time.Now()
	m1.State = core.MembershipActive
	m1.ActivatedAt = &activatedAt
	require.NoError(t, downstream.Storage().UpdateProjectMembership(ctx, m1))

	_, err = downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, project2.ID, userID, "viewer", 1))
	require.NoError(t, err)
	_, err = downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, otherUserID, "viewer", 1))
	require.NoError(t, err)

	rows, err := downstream.Storage().ListUserProjectMemberships(ctx, userID)
	require.NoError(t, err)
	require.Len(t, rows, 2, "userID has memberships in both projects")

	counts, err := downstream.Storage().CountProjectMembershipsByUsers(ctx, []uint{userID, otherUserID})
	require.NoError(t, err)
	require.Contains(t, counts, userID)
	assert.Equal(t, 1, counts[userID].Active, "one of userID's two memberships is active")
	assert.Equal(t, 2, counts[userID].Total)
	require.Contains(t, counts, otherUserID)
	assert.Equal(t, 0, counts[otherUserID].Active)
	assert.Equal(t, 1, counts[otherUserID].Total)
}

// TestMembershipProxy_CreateRejectsAdminRoleWithoutAuthority (#1578) proves
// CreateMembershipProxy re-derives inviteMemberWithMode's requireAuthorityForRole
// escalation-by-proxy ceiling before persisting a new membership row. `downstream`
// authenticates as a MACHINE credential (createNodeToken) — it holds system.write
// (the gate on the whole /system group) but no roles.assign and no admin-tier
// role anywhere, exactly the credential class this proxy is meant to serve. RED
// without the fix: this create would have succeeded, minting an admin-tier ACTIVE
// membership with no admin authority anywhere in the chain.
func TestMembershipProxy_CreateRejectsAdminRoleWithoutAuthority(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	now := time.Now()
	userID := mustCreateUser(t, upstream, "mem1578-target", "mem1578-target@example.com")

	m := buildInvitedMembership(now, projectID, userID, "admin", 0)
	m.State = core.MembershipActive
	activatedAt := now
	m.ActivatedAt = &activatedAt
	_, err := downstream.Storage().CreateProjectMembership(ctx, m)
	require.Error(t, err, "a system.write-only caller with no admin authority must not be able to grant an admin-tier active membership")
}

// TestMembershipProxy_CreateAllowsAdminRoleByGenuineAdmin (#1578) is the positive
// control: a genuine project admin creating a genuine admin-role membership must
// still succeed end-to-end over the proxy — mirrors
// TestInvitationProxy_CreateAllowsAdminRoleByGenuineAdmin exactly, including why
// the actor must authenticate as a real human session rather than the shared
// machine credential (RequireAuthorityForRole's ceiling is keyed off actorID(r),
// which is human-only by design and returns 0 for a machine actor).
func TestMembershipProxy_CreateAllowsAdminRoleByGenuineAdmin(t *testing.T) {
	upstream, _, projectID, baseURL := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	now := time.Now()
	const pw = "Qr7#Kp2$Lm5@Vn9!"

	admin, err := upstream.CreateUser(ctx, &core.CreateUserRequest{Username: "mem1578-admin", Email: "mem1578-admin@example.com", Password: pw})
	require.NoError(t, err)
	adminRole, err := upstream.Storage().GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, upstream.Storage().AssignRole(ctx, admin.ID, adminRole.ID, coreStorage.Scope{ProjectID: projectID}))
	grantSystemWrite(t, upstream, admin.ID)
	adminSess, _, err := upstream.Login(ctx, &core.LoginRequest{Username: "mem1578-admin", Password: pw})
	require.NoError(t, err)
	asAdmin := newDeleteProjectScopeRemoteClient(t, baseURL, adminSess.SessionToken)

	target, err := upstream.CreateUser(ctx, &core.CreateUserRequest{Username: "mem1578-grantee", Email: "mem1578-grantee@example.com", Password: pw})
	require.NoError(t, err)

	m := buildInvitedMembership(now, projectID, target.ID, "admin", admin.ID)
	m.State = core.MembershipActive
	activatedAt := now
	m.ActivatedAt = &activatedAt
	created, err := asAdmin.CreateProjectMembership(ctx, m)
	require.NoError(t, err, "a genuine admin creating a genuine admin-role membership must still succeed")
	assert.Equal(t, "admin", created.Role)
	assert.Equal(t, admin.ID, created.InvitedBy, "InvitedBy must be the authenticated admin, not the wire-supplied value")
}

// TestMembershipProxy_UpdateRejectsAdminRoleWithoutAuthority (#1578) proves
// UpdateMembershipProxy carries the same ceiling as CreateMembershipProxy. It is
// the more direct route: UpdateProjectMembership is a plain Save of the full row
// (see the proxy's doc comment), so it is the only code path anywhere — proxy or
// human-facing — that can rewrite an EXISTING membership's Role. The human-facing
// path never mutates Role post-invite (TransitionMembership only ever touches
// State). RED without the fix: this update would have succeeded, promoting an
// existing "viewer" membership straight to an active admin-tier one with no
// admin authority anywhere in the chain.
func TestMembershipProxy_UpdateRejectsAdminRoleWithoutAuthority(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForMemberships(t)
	ctx := context.Background()
	now := time.Now()
	userID := mustCreateUser(t, upstream, "mem1578-updatee", "mem1578-updatee@example.com")

	m, err := downstream.Storage().CreateProjectMembership(ctx, buildInvitedMembership(now, projectID, userID, "viewer", 0))
	require.NoError(t, err)

	activatedAt := time.Now()
	m.Role = "admin"
	m.State = core.MembershipActive
	m.ActivatedAt = &activatedAt
	err = downstream.Storage().UpdateProjectMembership(ctx, m)
	require.Error(t, err, "a system.write-only caller with no admin authority must not be able to promote an existing membership to an admin-tier role")

	// The row must be untouched by the rejected update.
	direct, err := upstream.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, "viewer", direct.Role, "a rejected update must not leave the role changed")
}
