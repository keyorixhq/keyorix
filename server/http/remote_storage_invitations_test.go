package http

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

// newUpstreamDownstreamForInvitations builds the standard #452/#507 two-server
// harness: an "upstream" exercised through the REAL production NewRouter/handlers
// (including the new /api/v1/system/invitations routes,
// server/http/handlers/invitations_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage. Mirrors
// remote_storage_login_rate_limit_test.go's harness exactly.
func newUpstreamDownstreamForInvitations(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore, projectID uint) {
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
	project, err := upstream.CreateProject(ctx, "Invitations Test Project", "")
	require.NoError(t, err)
	return upstream, downstream, project.ID
}

// buildPendingInvitation mirrors exactly what internal/core/invitations.go's
// InviteToProject computes before calling storage.CreateProjectInvitation — a
// fully-built, pending invitation with a 14-day TTL — WITHOUT going through
// InviteToProject itself. InviteToProject's own escalation-guard path first
// calls storage.GetRoleByName, whose RemoteStorage implementation requests
// GET /api/v1/roles/by-name/{name} — a route this codebase never registered
// (server/http/router.go has no such handler), an entirely separate,
// pre-existing bug independent of #507 (the same "implemented client method,
// missing server route" class #503 fixed for GetUserByEmail) that would
// otherwise block every test in this file. Flagged as a discovered follow-up
// in the PR, not fixed here — out of this finding's scope.
func buildPendingInvitation(now time.Time, projectID uint, email, role string, invitedBy uint) *models.ProjectInvitation {
	expires := now.Add(14 * 24 * time.Hour)
	return &models.ProjectInvitation{
		ProjectID:              projectID,
		Email:                  email,
		Role:                   role,
		State:                  core.InvitationPending,
		InvitedBy:              invitedBy,
		ValidationModeAtInvite: core.ValidationModeOpen,
		ExpiresAt:              &expires,
		CreatedAt:              now,
	}
}

// TestRemoteStorageInvitation_CreateGetList_RealServer proves the #507 fix for
// CreateProjectInvitation/GetProjectInvitation/ListProjectInvitations: an
// invitation is genuinely persisted on the upstream server via the DOWNSTREAM's
// RemoteStorage, fetchable by ID, and listed — all via storage.type: remote
// against a real router, not a protocol mock.
func TestRemoteStorageInvitation_CreateGetList_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForInvitations(t)
	ctx := context.Background()
	now := time.Now()

	inv, err := downstream.Storage().CreateProjectInvitation(ctx, buildPendingInvitation(now, projectID, "invitee@example.com", "viewer", 1))
	require.NoError(t, err, "creating an invitation must succeed via storage.type: remote")
	require.NotZero(t, inv.ID, "the upstream must assign a real ID")
	assert.Equal(t, "invitee@example.com", inv.Email)
	assert.Equal(t, "viewer", inv.Role)
	assert.Equal(t, core.InvitationPending, inv.State)
	assert.Equal(t, projectID, inv.ProjectID)
	assert.NotNil(t, inv.ExpiresAt, "the 14-day TTL must round-trip")

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, err)
	assert.Equal(t, "invitee@example.com", direct.Email)

	// GetProjectInvitation via the downstream (RemoteStorage) round-trips every
	// field correctly.
	fetched, err := downstream.Storage().GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, err)
	assert.Equal(t, inv.ID, fetched.ID)
	assert.Equal(t, inv.Email, fetched.Email)
	assert.Equal(t, inv.Role, fetched.Role)
	assert.Equal(t, inv.State, fetched.State)
	assert.Equal(t, inv.ProjectID, fetched.ProjectID)
	assert.WithinDuration(t, *inv.ExpiresAt, *fetched.ExpiresAt, time.Second)

	// A second invitation to a different email, then list both back via the
	// downstream's ListProjectInvitations.
	_, err = downstream.Storage().CreateProjectInvitation(ctx, buildPendingInvitation(now, projectID, "second@example.com", "viewer", 1))
	require.NoError(t, err)

	rows, err := downstream.Storage().ListProjectInvitations(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	emails := map[string]bool{}
	for _, r := range rows {
		emails[r.Email] = true
	}
	assert.True(t, emails["invitee@example.com"])
	assert.True(t, emails["second@example.com"])
}

// TestRemoteStorageInvitation_GetNotFound_RealServer proves a clean not-found
// error (not a panic, not a garbage 500) for a nonexistent invitation ID.
func TestRemoteStorageInvitation_GetNotFound_RealServer(t *testing.T) {
	_, downstream, _ := newUpstreamDownstreamForInvitations(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetProjectInvitation(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageInvitation_UpdateAlreadyResolved_RealServer proves that
// UpdateProjectInvitation's conditional write correctly reports ok=false (no
// error) once an invitation is no longer pending — exactly the signal
// RevokeInvitation/completeInvitationAccept rely on to detect a lost race.
func TestRemoteStorageInvitation_UpdateAlreadyResolved_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForInvitations(t)
	ctx := context.Background()
	now := time.Now()

	inv, err := downstream.Storage().CreateProjectInvitation(ctx, buildPendingInvitation(now, projectID, "resolved@example.com", "viewer", 1))
	require.NoError(t, err)

	// Resolve it once (accept) directly against the upstream's real storage.
	acceptedAt := time.Now()
	inv.State = core.InvitationAccepted
	inv.AcceptedAt = &acceptedAt
	ok, err := upstream.Storage().UpdateProjectInvitation(ctx, inv)
	require.NoError(t, err)
	require.True(t, ok, "the first transition off pending must succeed")

	// A second attempt via the DOWNSTREAM (over real HTTP) to revoke the SAME
	// already-accepted invitation must cleanly report ok=false, not an error and
	// not a silent false success.
	revokedAt := time.Now()
	attempt := &models.ProjectInvitation{ID: inv.ID, State: core.InvitationRevoked, RevokedAt: &revokedAt}
	ok, err = downstream.Storage().UpdateProjectInvitation(ctx, attempt)
	require.NoError(t, err)
	assert.False(t, ok, "an update against a non-pending invitation must not report success")

	// The invitation must still read as accepted (untouched by the failed revoke).
	final, err := downstream.Storage().GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, err)
	assert.Equal(t, core.InvitationAccepted, final.State)
}

// TestRemoteStorageInvitation_ConcurrentAcceptRace_RealServer is the critical
// #507 test: it fires N concurrent "accept" requests at the SAME pending
// invitation over real HTTP against the real upstream router, and asserts
// EXACTLY ONE succeeds — proving UpdateProjectInvitationProxy's conditional
// `WHERE id = ? AND state = 'pending'` write (local_invitations.go, proxied
// unchanged by server/http/handlers/invitations_proxy.go) still closes the
// double-accept TOCTOU race setup_consume.go's completeInvitationAccept depends
// on, even across a network hop — not a client-side
// "GET, check state, then PUT" sequence, which would reopen exactly this race.
func TestRemoteStorageInvitation_ConcurrentAcceptRace_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForInvitations(t)
	ctx := context.Background()
	now := time.Now()

	inv, err := downstream.Storage().CreateProjectInvitation(ctx, buildPendingInvitation(now, projectID, "race@example.com", "viewer", 1))
	require.NoError(t, err)

	const n = 20
	var successCount atomic.Int64
	var errCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			acceptedAt := time.Now()
			attempt := &models.ProjectInvitation{
				ID:         inv.ID,
				State:      core.InvitationAccepted,
				AcceptedAt: &acceptedAt,
			}
			ok, err := downstream.Storage().UpdateProjectInvitation(ctx, attempt)
			if err != nil {
				errCount.Add(1)
				return
			}
			if ok {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(0), errCount.Load(), "every concurrent accept attempt must get a clean result, not a transport/server error")
	assert.Equal(t, int64(1), successCount.Load(), "exactly one concurrent accept must win the race — the rest must cleanly lose, never a double grant")

	final, err := downstream.Storage().GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, err)
	assert.Equal(t, core.InvitationAccepted, final.State)
	assert.NotNil(t, final.AcceptedAt)
}

// TestInvitationProxy_CreateRejectsProjectAdminRoleWithoutAuthority (#1529)
// proves CreateInvitationProxy re-derives InviteToProject's
// requireAuthorityForRole escalation-by-proxy ceiling for a project-scoped
// invite. RED without the fix: this create would have succeeded, minting a
// pending admin-role invitation with no project-admin authority anywhere in
// the chain.
func TestInvitationProxy_CreateRejectsProjectAdminRoleWithoutAuthority(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForInvitations(t)
	ctx := context.Background()
	now := time.Now()

	nonAdmin, err := upstream.Storage().CreateUser(ctx, &models.User{Username: "inv1529-nonadmin", Email: "inv1529-nonadmin@example.com", IsActive: true})
	require.NoError(t, err)

	inv := buildPendingInvitation(now, projectID, "target@example.com", "admin", nonAdmin.ID)
	_, err = downstream.Storage().CreateProjectInvitation(ctx, inv)
	require.Error(t, err, "a non-admin caller must not be able to create a pending admin-role invitation")
}

// TestInvitationProxy_CreateRejectsGlobalSystemRoleWithoutAuthority (#1529)
// proves the same ceiling for a global invite's SystemRole. RED without the
// fix: this create would have succeeded.
func TestInvitationProxy_CreateRejectsGlobalSystemRoleWithoutAuthority(t *testing.T) {
	upstream, downstream, _ := newUpstreamDownstreamForInvitations(t)
	ctx := context.Background()
	now := time.Now()

	nonAdmin, err := upstream.Storage().CreateUser(ctx, &models.User{Username: "inv1529-nonadmin2", Email: "inv1529-nonadmin2@example.com", IsActive: true})
	require.NoError(t, err)

	expires := now.Add(14 * 24 * time.Hour)
	inv := &models.ProjectInvitation{
		Email: "target2@example.com", State: core.InvitationPending, InvitedBy: nonAdmin.ID,
		SystemRole: "system_admin", ValidationModeAtInvite: core.ValidationModeOpen,
		ExpiresAt: &expires, CreatedAt: now,
	}
	_, err = downstream.Storage().CreateProjectInvitation(ctx, inv)
	require.Error(t, err, "a non-admin caller must not be able to create a pending global system_admin invitation")
}

// TestInvitationProxy_CreateAllowsAdminRoleByGenuineAdmin (#1529) is the
// positive control: a genuine admin creating a genuine admin-role invitation
// must still succeed end-to-end over the proxy.
func TestInvitationProxy_CreateAllowsAdminRoleByGenuineAdmin(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForInvitations(t)
	ctx := context.Background()
	now := time.Now()

	admin, err := upstream.Storage().CreateUser(ctx, &models.User{Username: "inv1529-admin", Email: "inv1529-admin@example.com", IsActive: true})
	require.NoError(t, err)
	adminRole, err := upstream.Storage().GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, upstream.Storage().AssignRole(ctx, admin.ID, adminRole.ID, coreStorage.Scope{ProjectID: projectID}))

	inv := buildPendingInvitation(now, projectID, "target3@example.com", "admin", admin.ID)
	created, err := downstream.Storage().CreateProjectInvitation(ctx, inv)
	require.NoError(t, err, "a genuine admin creating a genuine admin-role invitation must still succeed")
	assert.Equal(t, "admin", created.Role)
}

// TestInvitationProxy_UpdateDoesNotRewriteIdentityUnderCoverOfTransition
// (#1529) proves UpdateInvitationProxy applies only the legitimate transition
// fields (State/AcceptedAt/RevokedAt) from the wire, discarding any
// caller-supplied identity fields (Email/Role/SystemRole/InvitedBy/ProjectID)
// — mirroring AR-001's field-narrowing fix for UpdateAccessRequestProxy. RED
// without the fix: the fetched row below would read the forged SystemRole
// and Email, not the original ones.
func TestInvitationProxy_UpdateDoesNotRewriteIdentityUnderCoverOfTransition(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForInvitations(t)
	ctx := context.Background()
	now := time.Now()

	inv, err := downstream.Storage().CreateProjectInvitation(ctx, buildPendingInvitation(now, projectID, "real-invitee@example.com", "viewer", 1))
	require.NoError(t, err)

	acceptedAt := time.Now()
	forged := &models.ProjectInvitation{
		ID:         inv.ID,
		Email:      "attacker@example.com", // forged identity rewrite attempt
		Role:       "admin",
		SystemRole: "super_admin",
		InvitedBy:  9999,
		State:      core.InvitationAccepted,
		AcceptedAt: &acceptedAt,
	}
	updated, err := downstream.Storage().UpdateProjectInvitation(ctx, forged)
	require.NoError(t, err)
	assert.True(t, updated, "the legitimate transition (pending -> accepted) must still succeed")

	fetched, err := downstream.Storage().GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, err)
	assert.Equal(t, core.InvitationAccepted, fetched.State, "the state transition itself must apply")
	assert.Equal(t, "real-invitee@example.com", fetched.Email, "the original email must survive, not the forged one")
	assert.Equal(t, "viewer", fetched.Role, "the original role must survive, not the forged admin role")
	assert.Empty(t, fetched.SystemRole, "no system role was ever set on this invitation; the forged one must not appear")
	assert.Equal(t, uint(1), fetched.InvitedBy, "the original inviter must survive, not the forged one")
	assert.Equal(t, projectID, fetched.ProjectID, "the original project must survive")
}
