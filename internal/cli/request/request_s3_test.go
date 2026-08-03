// request_s3_test.go – coverage push for cli/request: exercises the local-
// storage success paths (full function bodies) that the remote/s2 test files
// leave at <65% for runList, runAccess, runWithdraw, runSecretAccess, and
// runReview.
//
// Strategy:
//   - t.Chdir(t.TempDir()) + KEYORIX_SERVER="" → InitializeCoreService falls
//     back to ./secrets.db in the temp dir.
//   - The test seeds data by calling InitializeCoreService() itself (same file),
//     then calls the Run function; the command's own InitializeCoreService
//     opens the same file and sees the seeded rows.
package request

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// seedRequestDB seeds the minimal graph the request commands need.
// It returns the admin's user ID and the project ID.
func seedRequestDB(t *testing.T) (adminID, projectID uint, svc *core.KeyorixCore) {
	t.Helper()
	var err error
	svc, err = common.InitializeCoreService()
	require.NoError(t, err)

	svc.SetBootstrapToken("req-s3-token")
	ctx := context.Background()
	_, err = svc.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com",
		Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "req-s3-token",
	})
	require.NoError(t, err)

	u, err := svc.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	adminID = u.ID

	proj, err := svc.CreateProject(ctx, "testproj", "")
	require.NoError(t, err)
	projectID = proj.ID

	return
}

// seedSecretForRequest seeds a secret needed for secret-access request tests.
func seedSecretForRequest(t *testing.T, svc *core.KeyorixCore, ownerID, projectID uint) uint {
	t.Helper()
	ctx := context.Background()
	envs, err := svc.Storage().ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	secret, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "mysecret", Value: []byte("val"),
		Type:      "password",
		ProjectID: projectID, EnvironmentID: envs[0].ID,
		CreatedBy: "admin", OwnerID: ownerID,
	})
	require.NoError(t, err)
	return secret.ID
}

// ──────────────────────────── runAccess ────────────────────────────────────

// TestRunAccess_SuccessPath exercises the full runAccess body including the
// RequestProjectAccess call and the Printf at the end.
func TestRunAccess_SuccessPath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	// Create a regular user who will request access.
	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "requester", Email: "requester@example.com", IsActive: true,
	})
	require.NoError(t, err)
	_ = adminID
	_ = projectID

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
	accessRole = "viewer"
	accessReason = "I need access"

	require.NoError(t, runAccess(nil, nil))
}

// ──────────────────────────── runList ──────────────────────────────────────

// TestRunList_PrintsTable exercises the table-print path when access requests
// exist for the project.
func TestRunList_PrintsTable(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "listrequester", Email: "listrequester@example.com", IsActive: true,
	})
	require.NoError(t, err)

	_, err = svc.RequestProjectAccess(ctx, projectID, requester.ID, "viewer", "need it")
	require.NoError(t, err)
	_ = adminID

	orig := listProject
	defer func() { listProject = orig }()
	listProject = "testproj"

	require.NoError(t, runList(nil, nil))
}

// TestRunList_PrintsTableWithSecretID exercises the SecretID column in the
// table (when the request is a secret-scoped access request).
func TestRunList_PrintsTableWithSecretID(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	secretID := seedSecretForRequest(t, svc, adminID, projectID)

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "secreq", Email: "secreq@example.com", IsActive: true,
	})
	require.NoError(t, err)

	// RequestSecretAccess produces a secret-scoped AccessRequest with SecretID set.
	_, err = svc.RequestSecretAccess(ctx, secretID, requester.ID, "urgent")
	require.NoError(t, err)

	orig := listProject
	defer func() { listProject = orig }()
	listProject = "testproj"

	require.NoError(t, runList(nil, nil))
}

// ──────────────────────────── runWithdraw ──────────────────────────────────

// TestRunWithdraw_SuccessPath exercises the full runWithdraw body including the
// WithdrawAccessRequest call and the Printf confirmation.
func TestRunWithdraw_SuccessPath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "withdrawer", Email: "withdrawer@example.com", IsActive: true,
	})
	require.NoError(t, err)

	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "", "")
	require.NoError(t, err)

	origID, origUser := withdrawID, withdrawUser
	defer func() { withdrawID = origID; withdrawUser = origUser }()
	withdrawID = req.ID
	withdrawUser = requester.Email

	require.NoError(t, runWithdraw(nil, nil))
}

// ──────────────────────────── runSecretAccess ──────────────────────────────

// TestRunSecretAccess_SuccessPathWithID exercises the ID-based secret-access
// request path including the final Printf.
func TestRunSecretAccess_SuccessPathWithID(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	secretID := seedSecretForRequest(t, svc, adminID, projectID)

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "sa-requester", Email: "sa-requester@example.com", IsActive: true,
	})
	require.NoError(t, err)

	origUser, origID, origRef := secretAccessUser, secretAccessSecretID, secretAccessRef
	defer func() {
		secretAccessUser = origUser
		secretAccessSecretID = origID
		secretAccessRef = origRef
	}()
	secretAccessUser = requester.Email
	secretAccessSecretID = secretID
	secretAccessRef = ""

	require.NoError(t, runSecretAccess(nil, nil))
}

// TestRunSecretAccess_SuccessPathWithRef exercises the ref-based secret-access
// request path (ResolveSecretRef → ID lookup → RequestSecretAccess).
func TestRunSecretAccess_SuccessPathWithRef(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	// Get the default environment name to build the ref.
	envs, err := svc.Storage().ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "dbpass", Value: []byte("s"),
		Type: "password", ProjectID: projectID, EnvironmentID: envs[0].ID,
		CreatedBy: "admin", OwnerID: adminID,
	})
	require.NoError(t, err)

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "ref-requester", Email: "ref-requester@example.com", IsActive: true,
	})
	require.NoError(t, err)

	origUser, origID, origRef := secretAccessUser, secretAccessSecretID, secretAccessRef
	defer func() {
		secretAccessUser = origUser
		secretAccessSecretID = origID
		secretAccessRef = origRef
	}()
	secretAccessUser = requester.Email
	secretAccessSecretID = 0
	// Ref format: "project/environment/name"
	secretAccessRef = "testproj/" + envs[0].Name + "/dbpass"

	require.NoError(t, runSecretAccess(nil, nil))
}

// ──────────────────────────── runReview ────────────────────────────────────

// TestRunReview_RejectPath_Success exercises the full reject flow including
// the final "rejected" printf.
func TestRunReview_RejectPath_Success(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "rejreq", Email: "rejreq@example.com", IsActive: true,
	})
	require.NoError(t, err)

	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "viewer", "need")
	require.NoError(t, err)
	_ = adminID

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
	reviewReason = "not eligible"
	reviewTTL = ""

	require.NoError(t, runReview(nil, nil))
}

// TestRunReview_ApprovePath_Permanent_Success exercises the approve flow with no
// TTL (permanent grant) and checks the "permanently" printf path.
func TestRunReview_ApprovePath_Permanent_Success(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "appreq", Email: "appreq@example.com", IsActive: true,
	})
	require.NoError(t, err)
	_ = adminID

	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "viewer", "need")
	require.NoError(t, err)

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

	require.NoError(t, runReview(nil, nil))
}

// TestRunReview_ApprovePath_TimeBound_Success exercises the approve flow with a
// TTL (time-bound grant) — covers the grantNote := fmt.Sprintf("for %s...") branch.
func TestRunReview_ApprovePath_TimeBound_Success(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "appreq2", Email: "appreq2@example.com", IsActive: true,
	})
	require.NoError(t, err)
	_ = adminID

	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "viewer", "")
	require.NoError(t, err)

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
	reviewTTL = "72h"

	require.NoError(t, runReview(nil, nil))
}

// TestRunReview_ApprovePath_InvalidTTL exercises the TTL parse error path.
func TestRunReview_ApprovePath_InvalidTTL_Detail(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "appreq3", Email: "appreq3@example.com", IsActive: true,
	})
	require.NoError(t, err)
	_ = adminID

	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "", "")
	require.NoError(t, err)

	origID, origAction, origBy, origTTL :=
		reviewID, reviewAction, reviewBy, reviewTTL
	defer func() {
		reviewID = origID
		reviewAction = origAction
		reviewBy = origBy
		reviewTTL = origTTL
	}()
	reviewID = req.ID
	reviewAction = "approve"
	reviewBy = "admin@example.com"
	reviewTTL = "-1h" // negative duration — must be rejected

	err = runReview(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--ttl must be a non-negative Go duration")
}

// TestRunReview_RejectAuthFails exercises the requireReviewAuthority path when
// the --by actor does NOT hold roles.assign (err != nil from Authorize is
// triggered by using a user who doesn't exist in the DB at all — GetUser
// internally would return a storage error).
func TestRunReview_RejectAuth_UnprivilegedUser(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "unauth-req", Email: "unauth-req@example.com", IsActive: true,
	})
	require.NoError(t, err)

	// Create a plain viewer with no roles.assign.
	viewer, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "viewer-only", Email: "viewer@example.com", IsActive: true,
	})
	require.NoError(t, err)

	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "", "")
	require.NoError(t, err)

	origID, origAction, origBy :=
		reviewID, reviewAction, reviewBy
	defer func() {
		reviewID = origID
		reviewAction = origAction
		reviewBy = origBy
	}()
	reviewID = req.ID
	reviewAction = "reject"
	reviewBy = viewer.Email

	err = runReview(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "roles.assign")
}

// TestRunReview_ApproveSecretScoped exercises the secret-scoped approval branch
// (existing.SecretID != nil), including the "role and ttl do not apply" guard.
func TestRunReview_ApproveSecretScoped_InvalidRoleOrTTL(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	secretID := seedSecretForRequest(t, svc, adminID, projectID)

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "sareq2", Email: "sareq2@example.com", IsActive: true,
	})
	require.NoError(t, err)

	req, err := svc.RequestSecretAccess(ctx, secretID, requester.ID, "urgent")
	require.NoError(t, err)

	origID, origAction, origBy, origRole :=
		reviewID, reviewAction, reviewBy, reviewRole
	defer func() {
		reviewID = origID
		reviewAction = origAction
		reviewBy = origBy
		reviewRole = origRole
	}()
	reviewID = req.ID
	reviewAction = "approve"
	reviewBy = "admin@example.com"
	reviewRole = "viewer" // must be rejected: role doesn't apply to secret-scoped

	err = runReview(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "do not apply to a secret-scoped request")
}

// TestRunReview_ApproveSecretScoped_Success exercises the happy path for
// approving a secret-scoped access request.
func TestRunReview_ApproveSecretScoped_Success(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	adminID, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	secretID := seedSecretForRequest(t, svc, adminID, projectID)

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "sareq3", Email: "sareq3@example.com", IsActive: true,
	})
	require.NoError(t, err)

	req, err := svc.RequestSecretAccess(ctx, secretID, requester.ID, "urgent")
	require.NoError(t, err)

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

	require.NoError(t, runReview(nil, nil))
}

// TestRunReview_AccessRequestNotFound covers the "access request not found"
// error branch in runReview.
func TestRunReview_AccessRequestNotFound(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// Seed the DB so that service init succeeds and resolveUserID finds admin.
	_, _, _ = seedRequestDB(t)

	origID, origAction, origBy := reviewID, reviewAction, reviewBy
	defer func() { reviewID = origID; reviewAction = origAction; reviewBy = origBy }()
	reviewID = 99999 // no such request
	reviewAction = "reject"
	reviewBy = "admin@example.com"

	err := runReview(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}
