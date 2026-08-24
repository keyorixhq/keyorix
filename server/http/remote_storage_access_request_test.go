// remote_storage_access_request_test.go — end-to-end coverage for #523:
// RemoteStorage's CreateAccessRequest/GetAccessRequest/UpdateAccessRequest/
// ListAccessRequests/CreateAccessRequestApproval/ListAccessRequestApprovals
// were entirely stubbed, so the ENTIRE self-service access-request workflow
// (request/list/approve/reject/withdraw, ADR-024) was 100% broken under
// storage.type: remote. Mirrors remote_storage_sso_state_test.go's #521
// harness exactly: a real "upstream" exercised through the production
// NewRouter/handlers (including the new /api/v1/system/access-requests
// routes, server/http/handlers/access_request_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote pointed at
// "upstream" over real HTTP via store.RemoteStorage.
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

// newUpstreamDownstreamForAccessRequests builds the standard
// #452/#507/#510/#521/#523 two-server harness: an "upstream" exercised
// through the REAL production NewRouter/handlers, and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed
// at "upstream" over real HTTP via store.RemoteStorage. Returns the upstream
// core and a live project ID (BootstrapSystem seeds one) alongside both
// cores.
func newUpstreamDownstreamForAccessRequests(t *testing.T) (upstream, downstream *core.KeyorixCore, projectID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createNodeToken(t, upstream)

	projects, err := upstream.ListProjects(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, projects, "BootstrapSystem must seed at least one project")
	projectID = projects[0].ID

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
	return upstream, downstream, projectID
}

// buildAccessRequest mirrors what internal/core/invitations.go's
// RequestProjectAccess computes before calling storage.CreateAccessRequest —
// a fully-built, pending request — WITHOUT going through RequestProjectAccess
// itself, so the storage-primitive tests below can exercise
// CreateAccessRequest/GetAccessRequest/UpdateAccessRequest directly.
func buildAccessRequest(now time.Time, projectID, userID uint, suggestedRole string) *models.AccessRequest {
	expires := now.Add(72 * time.Hour)
	return &models.AccessRequest{
		ProjectID:     projectID,
		UserID:        userID,
		SuggestedRole: suggestedRole,
		State:         "pending",
		Reason:        "need access for on-call rotation",
		ExpiresAt:     &expires,
		CreatedAt:     now,
	}
}

// TestRemoteStorageAccessRequest_CreateGetList_RealServer proves the #523 fix:
// an access request is genuinely persisted on the upstream server via the
// DOWNSTREAM's RemoteStorage, retrievable by ID, and listed by project — all
// via storage.type: remote against a real router, not a protocol mock.
func TestRemoteStorageAccessRequest_CreateGetList_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForAccessRequests(t)
	ctx := context.Background()
	now := time.Now()

	req := buildAccessRequest(now, projectID, 42, "developer")
	created, err := downstream.Storage().CreateAccessRequest(ctx, req)
	require.NoError(t, err, "creating an access request must succeed via storage.type: remote")
	require.NotZero(t, created.ID, "the upstream must assign a real ID")

	// Confirm it is a REAL row in the upstream's own storage (not just "the
	// call didn't error"), by fetching it directly against upstream.
	direct, err := upstream.Storage().GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "developer", direct.SuggestedRole)
	assert.Equal(t, "pending", direct.State)

	// Fetching via the downstream (RemoteStorage) round-trips every field.
	fetched, err := downstream.Storage().GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, projectID, fetched.ProjectID)
	assert.Equal(t, uint(42), fetched.UserID)
	assert.Equal(t, "developer", fetched.SuggestedRole)
	assert.Equal(t, "need access for on-call rotation", fetched.Reason)
	assert.Equal(t, "pending", fetched.State)
	require.NotNil(t, fetched.ExpiresAt)
	assert.WithinDuration(t, now.Add(72*time.Hour), *fetched.ExpiresAt, time.Second)

	// A second, unrelated request in the same project must both list.
	req2 := buildAccessRequest(now, projectID, 43, "viewer")
	_, err = downstream.Storage().CreateAccessRequest(ctx, req2)
	require.NoError(t, err)

	rows, err := downstream.Storage().ListAccessRequests(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	userIDs := []uint{rows[0].UserID, rows[1].UserID}
	assert.ElementsMatch(t, []uint{42, 43}, userIDs)
}

// TestRemoteStorageAccessRequest_GetUnknown_RealServer proves a clean
// not-found error (not a panic, not a garbage 500) for a request that was
// never created.
func TestRemoteStorageAccessRequest_GetUnknown_RealServer(t *testing.T) {
	_, downstream, _ := newUpstreamDownstreamForAccessRequests(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetAccessRequest(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageAccessRequest_UpdateConditional_RealServer proves
// UpdateAccessRequestProxy performs the SAME conditional
// `WHERE id = ? AND state = 'pending'` write local_invitations.go's
// UpdateAccessRequest does, end-to-end over HTTP: a first transition off
// "pending" succeeds and reports updated=true; a second transition attempt
// against the now-non-pending row reports updated=false rather than silently
// clobbering it — the #277 race guarantee ApproveAccessRequestWithExpiry/
// RejectAccessRequest/WithdrawAccessRequest all depend on.
func TestRemoteStorageAccessRequest_UpdateConditional_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForAccessRequests(t)
	ctx := context.Background()
	now := time.Now()

	req := buildAccessRequest(now, projectID, 7, "developer")
	created, err := downstream.Storage().CreateAccessRequest(ctx, req)
	require.NoError(t, err)

	// First transition: pending -> approved. Must match the row.
	created.State = "approved"
	created.GrantedRole = "developer"
	resolvedAt := now.Add(time.Minute)
	created.ResolvedAt = &resolvedAt
	created.ResolvedBy = 99
	updated, err := downstream.Storage().UpdateAccessRequest(ctx, created)
	require.NoError(t, err)
	assert.True(t, updated, "the first conditional update against a still-pending row must succeed")

	fetched, err := downstream.Storage().GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", fetched.State)
	assert.Equal(t, "developer", fetched.GrantedRole)

	// Second transition attempt (e.g. a concurrent reject/withdraw that lost
	// the race): the row is no longer "pending", so this must cleanly report
	// updated=false, NOT silently overwrite the already-approved row.
	fetched.State = "rejected"
	updatedAgain, err := downstream.Storage().UpdateAccessRequest(ctx, fetched)
	require.NoError(t, err)
	assert.False(t, updatedAgain, "an update against a non-pending row must not match")

	stillApproved, err := downstream.Storage().GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", stillApproved.State, "the losing update must not have clobbered the winner")
}

// TestRemoteStorageAccessRequest_ConcurrentUpdateRace_RealServer is the
// critical #523 test: it fires N concurrent conditional updates at the SAME
// pending access request over real HTTP against the real upstream router,
// and asserts EXACTLY ONE succeeds — proving UpdateAccessRequestProxy's
// direct passthrough onto local_invitations.go's conditional
// `WHERE id = ? AND state = 'pending'` UPDATE still closes the
// double-approve/reject/withdraw TOCTOU race, even across a network hop —
// not a client-side "GET, then PUT" sequence, which would reopen exactly
// this race. Mirrors #521's
// TestRemoteStorageSSOState_ConcurrentConsumeRace_RealServer exactly.
func TestRemoteStorageAccessRequest_ConcurrentUpdateRace_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForAccessRequests(t)
	ctx := context.Background()
	now := time.Now()

	req := buildAccessRequest(now, projectID, 11, "developer")
	created, err := downstream.Storage().CreateAccessRequest(ctx, req)
	require.NoError(t, err)

	const n = 20
	var successCount atomic.Int64
	var failCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			resolvedAt := now.Add(time.Duration(i) * time.Second)
			candidate := &models.AccessRequest{
				ID:            created.ID,
				ProjectID:     created.ProjectID,
				UserID:        created.UserID,
				SuggestedRole: created.SuggestedRole,
				GrantedRole:   "developer",
				State:         "approved",
				ExpiresAt:     created.ExpiresAt,
				CreatedAt:     created.CreatedAt,
				ResolvedBy:    uint(i + 1),
				ResolvedAt:    &resolvedAt,
			}
			updated, err := downstream.Storage().UpdateAccessRequest(ctx, candidate)
			if err != nil || !updated {
				failCount.Add(1)
				return
			}
			successCount.Add(1)
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int64(1), successCount.Load(), "exactly one concurrent conditional update must win the race — the rest must cleanly report updated=false, never a double-resolve")
	assert.Equal(t, int64(n-1), failCount.Load())
}

// TestRemoteStorageAccessRequest_Approvals_RealServer proves
// CreateAccessRequestApproval/ListAccessRequestApprovals round-trip over the
// proxy, and that the DB-level unique-index-backed
// ON CONFLICT (request_id, approver_id) DO NOTHING guard survives the HTTP
// hop: a duplicate sign-off from the same approver is a benign no-op, not a
// second row (which would defeat the M-of-K dual-control count).
func TestRemoteStorageAccessRequest_Approvals_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForAccessRequests(t)
	ctx := context.Background()
	now := time.Now()

	req := buildAccessRequest(now, projectID, 21, "developer")
	created, err := downstream.Storage().CreateAccessRequest(ctx, req)
	require.NoError(t, err)

	approvals, err := downstream.Storage().ListAccessRequestApprovals(ctx, created.ID)
	require.NoError(t, err)
	assert.Empty(t, approvals)

	err = downstream.Storage().CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{
		RequestID: created.ID, ApproverID: 100, CreatedAt: now,
	})
	require.NoError(t, err)
	err = downstream.Storage().CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{
		RequestID: created.ID, ApproverID: 200, CreatedAt: now,
	})
	require.NoError(t, err)

	approvals, err = downstream.Storage().ListAccessRequestApprovals(ctx, created.ID)
	require.NoError(t, err)
	require.Len(t, approvals, 2)
	approverIDs := []uint{approvals[0].ApproverID, approvals[1].ApproverID}
	assert.ElementsMatch(t, []uint{100, 200}, approverIDs)

	// Duplicate sign-off from approver 100 must be a benign no-op, not a
	// second row.
	err = downstream.Storage().CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{
		RequestID: created.ID, ApproverID: 100, CreatedAt: now.Add(time.Second),
	})
	require.NoError(t, err)

	approvals, err = downstream.Storage().ListAccessRequestApprovals(ctx, created.ID)
	require.NoError(t, err)
	assert.Len(t, approvals, 2, "a duplicate approver sign-off must not insert a second row")
}

// seedAccessRequestSecretFixture creates a project, a requester (owner of the
// secret and project viewer), a real user with NO special authority, a real
// admin, and a restricted secret with one version — mirroring
// internal/core/classification_gate_test.go's seedClassificationGateFixture
// exactly, against the upstream's own storage so the fixture is real rows,
// not a mock.
func seedAccessRequestSecretFixture(t *testing.T, upstream *core.KeyorixCore) (secretID, requesterID, nonAdminID, adminID, projectID uint) {
	t.Helper()
	ctx := context.Background()
	st := upstream.Storage()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "ar-1529-fixture"})
	require.NoError(t, err)

	requester, err := st.CreateUser(ctx, &models.User{Username: "ar1529-requester", Email: "ar1529-requester@example.com", IsActive: true})
	require.NoError(t, err)
	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, requester.ID, viewerRole.ID, coreStorage.Scope{ProjectID: proj.ID}))

	nonAdmin, err := st.CreateUser(ctx, &models.User{Username: "ar1529-nonadmin", Email: "ar1529-nonadmin@example.com", IsActive: true})
	require.NoError(t, err)

	admin, err := st.CreateUser(ctx, &models.User{Username: "ar1529-admin", Email: "ar1529-admin@example.com", IsActive: true})
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, admin.ID, adminRole.ID, coreStorage.Scope{}))

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "ar1529-secret", ProjectID: proj.ID, EnvironmentID: 1, Type: "password",
		IsSecret: true, OwnerID: requester.ID, Status: "active", Classification: "restricted",
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t-value"),
	})
	require.NoError(t, err)

	return secret.ID, requester.ID, nonAdmin.ID, admin.ID, proj.ID
}

// TestAccessRequestProxy_CreateRejectsNonPendingState (#1529) proves
// CreateAccessRequestProxy no longer accepts a caller-supplied non-pending
// State. Before the fix, POST {state:"approved", secret_id, user_id:self}
// created an access request that read as already-approved on its very first
// GET, bypassing ApproveSecretAccessRequest's dual control entirely — the
// CRITICAL finding. RED without the fix: the create below would have
// succeeded and the fetched row would have read State=="approved".
func TestAccessRequestProxy_CreateRejectsNonPendingState(t *testing.T) {
	upstream, downstream, _ := newUpstreamDownstreamForAccessRequests(t)
	secretID, requesterID, _, _, projectID := seedAccessRequestSecretFixture(t, upstream)
	ctx := context.Background()
	sid := secretID

	forged := &models.AccessRequest{
		ProjectID: projectID, UserID: requesterID, SecretID: &sid,
		State: "approved", ResolvedBy: requesterID, CreatedAt: time.Now(),
	}
	_, err := downstream.Storage().CreateAccessRequest(ctx, forged)
	require.Error(t, err, "creating an access request pre-approved must be refused")
}

// TestAccessRequestProxy_UpdateApprove_RejectsSelfApproval (#1529) proves
// UpdateAccessRequestProxy re-derives ApproveSecretAccessRequest's maker≠checker
// check. RED without the fix: this update would have succeeded.
func TestAccessRequestProxy_UpdateApprove_RejectsSelfApproval(t *testing.T) {
	upstream, downstream, _ := newUpstreamDownstreamForAccessRequests(t)
	secretID, requesterID, _, _, projectID := seedAccessRequestSecretFixture(t, upstream)
	ctx := context.Background()
	sid := secretID

	req, err := downstream.Storage().CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: projectID, UserID: requesterID, SecretID: &sid, State: "pending", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	req.State = "approved"
	req.ResolvedBy = requesterID // the requester approving their own request
	now := time.Now()
	req.ResolvedAt = &now
	_, err = downstream.Storage().UpdateAccessRequest(ctx, req)
	require.Error(t, err, "a requester approving their own access request must be refused")
}

// TestAccessRequestProxy_UpdateApprove_RejectsNonAdminApprover (#1529) proves
// UpdateAccessRequestProxy re-derives ApproveSecretAccessRequest's
// admin-authority ceiling for a secret-scoped request. This is the CRITICAL
// finding itself: before the fix, ANY caller holding only system.write (no
// admin authority at all) could approve access to a restricted secret via
// this raw call. RED without the fix: this update would have succeeded.
func TestAccessRequestProxy_UpdateApprove_RejectsNonAdminApprover(t *testing.T) {
	upstream, downstream, _ := newUpstreamDownstreamForAccessRequests(t)
	secretID, requesterID, nonAdminID, _, projectID := seedAccessRequestSecretFixture(t, upstream)
	ctx := context.Background()
	sid := secretID

	req, err := downstream.Storage().CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: projectID, UserID: requesterID, SecretID: &sid, State: "pending", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	req.State = "approved"
	req.ResolvedBy = nonAdminID // real user, real account, zero admin authority
	now := time.Now()
	req.ResolvedAt = &now
	_, err = downstream.Storage().UpdateAccessRequest(ctx, req)
	require.Error(t, err, "a non-admin approver must not be able to approve access to a restricted secret")

	// The row must still read pending — the rejected attempt must not have
	// partially applied.
	fetched, err := downstream.Storage().GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending", fetched.State)
}

// TestAccessRequestProxy_UpdateApprove_AllowsAdminApprover (#1529) is the
// positive control: a genuine admin approving a genuine restricted-secret
// request must still succeed end-to-end over the proxy — the fix closes the
// bypass without breaking the legitimate path.
func TestAccessRequestProxy_UpdateApprove_AllowsAdminApprover(t *testing.T) {
	upstream, downstream, _ := newUpstreamDownstreamForAccessRequests(t)
	secretID, requesterID, _, adminID, projectID := seedAccessRequestSecretFixture(t, upstream)
	ctx := context.Background()
	sid := secretID

	req, err := downstream.Storage().CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: projectID, UserID: requesterID, SecretID: &sid, State: "pending", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	req.State = "approved"
	req.ResolvedBy = adminID
	now := time.Now()
	req.ResolvedAt = &now
	updated, err := downstream.Storage().UpdateAccessRequest(ctx, req)
	require.NoError(t, err, "a genuine admin approving a genuine request must still succeed")
	assert.True(t, updated)

	fetched, err := downstream.Storage().GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", fetched.State)
	assert.Equal(t, adminID, fetched.ResolvedBy)
}
