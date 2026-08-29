// request_s24_test.go — coverage push targeting the ~11 % gap left after
// request_s3_test.go: the error-return branches inside runAccess, runList,
// runWithdraw, runSecretAccess, and runReview that are only reachable when
// the DB is live but the operation itself fails (bad ID, duplicate, wrong
// state, etc.), plus the runList empty-result branch.
//
// All tests follow the same pattern as request_s3_test.go:
//
//	t.Chdir(t.TempDir()) + KEYORIX_SERVER="" → InitializeCoreService opens
//	./secrets.db; seedRequestDB seeds that same file; the Run function's
//	own InitializeCoreService opens the same file and sees the seeded rows.
package request

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── runList — empty result ───────────────────────

// TestRunList_EmptyProject exercises the "No access requests found." branch
// (len(requests) == 0). The project exists but has no access requests yet.
func TestRunList_EmptyProject(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedRequestDB(t)

	orig := listProject
	defer func() { listProject = orig }()
	listProject = "testproj"

	// #G72: runList now requires --by and verifies roles.assign before listing;
	// the bootstrap admin seeded by seedRequestDB is authorized.
	origBy := listBy
	defer func() { listBy = origBy }()
	listBy = "admin@example.com"

	// Project exists, zero requests → must print "No access requests found."
	// and return nil (not an error).
	require.NoError(t, runList(nil, nil))
}

// ──────────────────────────── runAccess — error paths ──────────────────────

// TestRunAccess_UserNotFound exercises the resolveUserID-error branch: the
// project exists but the requested user email is unknown.
func TestRunAccess_UserNotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedRequestDB(t)

	origUser, origProject, origRole, origReason :=
		accessUser, accessProject, accessRole, accessReason
	defer func() {
		accessUser = origUser
		accessProject = origProject
		accessRole = origRole
		accessReason = origReason
	}()
	accessUser = "nobody@example.com" // not in DB
	accessProject = "testproj"
	accessRole = ""
	accessReason = ""

	err := runAccess(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no user found")
}

// TestRunAccess_RequestProjectAccessFails exercises the
// RequestProjectAccess-error branch by asking for an unknown role name (the
// core service validates it against the role catalog before touching the
// access_requests table).
func TestRunAccess_RequestProjectAccessFails(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "acc-reqfail", Email: "acc-reqfail@example.com", IsActive: true,
	})
	require.NoError(t, err)

	origUser, origProject, origRole, origReason :=
		accessUser, accessProject, accessRole, accessReason
	defer func() {
		accessUser = origUser
		accessProject = origProject
		accessRole = origRole
		accessReason = origReason
	}()
	accessUser = requester.Email
	accessProject = "testproj"
	accessRole = "nonexistent_role_xyz" // unknown → RequestProjectAccess returns error
	accessReason = ""

	err = runAccess(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to request access")
}

// ──────────────────────────── runWithdraw — error path ─────────────────────

// TestRunWithdraw_RequestNotFound exercises the WithdrawAccessRequest-error
// branch: the user is known but the request ID does not exist.
func TestRunWithdraw_RequestNotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedRequestDB(t)

	origID, origUser := withdrawID, withdrawUser
	defer func() { withdrawID = origID; withdrawUser = origUser }()
	withdrawID = 99999 // no such request
	withdrawUser = "admin@example.com"

	err := runWithdraw(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to withdraw")
}

// ──────────────────────────── runSecretAccess — error paths ────────────────

// TestRunSecretAccess_RequestSecretAccessFails exercises the
// RequestSecretAccess-error branch by supplying a secret ID that does not
// exist in the database.
func TestRunSecretAccess_RequestSecretAccessFails(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "sa-fail", Email: "sa-fail@example.com", IsActive: true,
	})
	require.NoError(t, err)

	origUser, origID, origRef := secretAccessUser, secretAccessSecretID, secretAccessRef
	defer func() {
		secretAccessUser = origUser
		secretAccessSecretID = origID
		secretAccessRef = origRef
	}()
	secretAccessUser = requester.Email
	secretAccessSecretID = 99999 // no such secret
	secretAccessRef = ""

	err = runSecretAccess(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to request secret access")
}

// ──────────────────────────── runReview — error paths ──────────────────────

// TestRunReview_RejectFailsOnAlreadyRejected exercises the
// RejectAccessRequest-error branch by rejecting a request that was already
// rejected (state is no longer "pending").
func TestRunReview_RejectFailsOnAlreadyRejected(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "rej2x-req", Email: "rej2x-req@example.com", IsActive: true,
	})
	require.NoError(t, err)
	_ = adminID

	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "", "test")
	require.NoError(t, err)

	// First rejection succeeds via the core directly so we don't rely on a second
	// CLI init opening the same file (same svc instance — no ambiguity).
	admin, err := svc.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	_, err = svc.RejectAccessRequest(ctx, projectID, req.ID, admin.ID, 0, "first")
	require.NoError(t, err)

	// Now try to reject via the CLI — the request is no longer pending.
	origID, origAction, origBy, origReason, origTTL :=
		reviewID, reviewAction, reviewBy, reviewReason, reviewTTL
	defer func() {
		reviewID = origID
		reviewAction = origAction
		reviewBy = origBy
		reviewReason = origReason
		reviewTTL = origTTL
	}()
	reviewID = req.ID
	reviewAction = "reject"
	reviewBy = "admin@example.com"
	reviewReason = "duplicate"
	reviewTTL = ""

	err = runReview(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to reject")
}

// TestRunReview_ApproveFailsOnAlreadyApproved exercises the
// ApproveAccessRequestWithExpiry-error branch by approving a request that was
// already approved (state is no longer "pending").
func TestRunReview_ApproveFailsOnAlreadyApproved(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "app2x-req", Email: "app2x-req@example.com", IsActive: true,
	})
	require.NoError(t, err)
	_ = adminID

	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "viewer", "need")
	require.NoError(t, err)

	// First approval via core directly — puts state = "approved".
	admin, err := svc.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	_, err = svc.ApproveAccessRequestWithExpiry(ctx, projectID, req.ID, admin.ID, 0, "viewer", 0)
	require.NoError(t, err)

	// Now try to approve again via the CLI — must hit the error branch.
	origID, origAction, origBy, origRole, origTTL :=
		reviewID, reviewAction, reviewBy, reviewRole, reviewTTL
	defer func() {
		reviewID = origID
		reviewAction = origAction
		reviewBy = origBy
		reviewRole = origRole
		reviewTTL = origTTL
	}()
	reviewID = req.ID
	reviewAction = "approve"
	reviewBy = "admin@example.com"
	reviewRole = "viewer"
	reviewTTL = ""

	err = runReview(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to approve access request")
}

// TestRunReview_ApproveSecretScopedFailsOnAlreadyApproved exercises the
// ApproveSecretAccessRequest-error branch by approving a secret-scoped request
// that was already approved (state is no longer "pending").
func TestRunReview_ApproveSecretScopedFailsOnAlreadyApproved(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	secretID := seedSecretForRequest(t, svc, adminID, projectID)

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "sareq-app2x", Email: "sareq-app2x@example.com", IsActive: true,
	})
	require.NoError(t, err)

	req, err := svc.RequestSecretAccess(ctx, secretID, requester.ID, "urgent")
	require.NoError(t, err)

	// First approval via core — moves state to "approved".
	admin, err := svc.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	_, err = svc.ApproveSecretAccessRequest(ctx, req.ID, admin.ID)
	require.NoError(t, err)

	// Now try to approve again via CLI — must hit the error branch.
	origID, origAction, origBy, origRole, origTTL :=
		reviewID, reviewAction, reviewBy, reviewRole, reviewTTL
	defer func() {
		reviewID = origID
		reviewAction = origAction
		reviewBy = origBy
		reviewRole = origRole
		reviewTTL = origTTL
	}()
	reviewID = req.ID
	reviewAction = "approve"
	reviewBy = "admin@example.com"
	reviewRole = ""
	reviewTTL = ""

	err = runReview(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to approve secret access request")
}
