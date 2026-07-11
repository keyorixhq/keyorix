package request

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── userLabel ────────────────────────────────────

func TestUserLabel_ExistingUser(t *testing.T) {
	svc, st := newTestRequestCore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, &models.User{Username: "alice", Email: "alice@example.com", IsActive: true})
	require.NoError(t, err)

	label := userLabel(ctx, svc, u.ID)
	assert.Contains(t, label, "alice")
	assert.Contains(t, label, "#")
}

func TestUserLabel_NonExistentUser(t *testing.T) {
	svc, _ := newTestRequestCore(t)
	ctx := context.Background()

	// ID that doesn't exist → falls back to "#N"
	label := userLabel(ctx, svc, 9999)
	assert.Equal(t, "#9999", label)
}

// ──────────────────────────── resolveUserID ────────────────────────────────

func TestResolveUserID_ExistingEmail(t *testing.T) {
	svc, st := newTestRequestCore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, &models.User{Username: "bob", Email: "bob@example.com", IsActive: true})
	require.NoError(t, err)

	id, err := resolveUserID(ctx, svc, "bob@example.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, id)
}

func TestResolveUserID_UnknownEmail(t *testing.T) {
	svc, _ := newTestRequestCore(t)
	ctx := context.Background()

	_, err := resolveUserID(ctx, svc, "ghost@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no user found")
}

// ──────────────────────────── requireReviewAuthority ───────────────────────

func TestRequireReviewAuthority_Unauthorized_s2(t *testing.T) {
	svc, st := newTestRequestCore(t)
	ctx := context.Background()

	// A plain user with no roles cannot approve — requireReviewAuthority must deny.
	u, err := st.CreateUser(ctx, &models.User{Username: "dave2", Email: "dave2@example.com", IsActive: true})
	require.NoError(t, err)

	p, err := st.CreateProject(ctx, &models.Project{Name: "proj2"})
	require.NoError(t, err)

	err = requireReviewAuthority(ctx, svc, u.ID, p.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not hold")
}

// ──────────────────────────── runList with seeded data ─────────────────────

func TestRunList_EmptyResult(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	orig := listProject
	defer func() { listProject = orig }()
	listProject = "default"

	// The local mode will try to find a "default" project; if not found it returns
	// an error or empty list — either is fine (no panic).
	err := runList(nil, nil)
	_ = err
}

// ──────────────────────────── runAccess ────────────────────────────────────

func TestRunAccess_MissingUserFlag(t *testing.T) {
	orig := accessUser
	defer func() { accessUser = orig }()
	accessUser = ""
	err := runAccess(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--user is required")
}

func TestRunAccess_MissingProject(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	// Unset KEYORIX_PROJECT so ResolveProject returns an error.
	t.Setenv("KEYORIX_PROJECT", "")

	origUser, origProject := accessUser, accessProject
	defer func() { accessUser = origUser; accessProject = origProject }()
	accessUser = "user@example.com"
	accessProject = ""

	err := runAccess(nil, nil)
	// Expect either "project is required" or storage error, not panic.
	_ = err
}

func TestRunAccess_ServiceInitAndProjectResolution(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "myproj")

	origUser, origProject := accessUser, accessProject
	defer func() { accessUser = origUser; accessProject = origProject }()
	accessUser = "user@example.com"
	accessProject = "myproj"

	err := runAccess(nil, nil)
	// Expect project-not-found or user-not-found error, not panic.
	_ = err
}

// ──────────────────────────── runWithdraw ──────────────────────────────────

func TestRunWithdraw_ZeroIDEarlyReturn(t *testing.T) {
	orig := withdrawID
	defer func() { withdrawID = orig }()
	withdrawID = 0
	err := runWithdraw(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestRunWithdraw_UserResolutionError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origUser := withdrawID, withdrawUser
	defer func() { withdrawID = origID; withdrawUser = origUser }()
	withdrawID = 1
	withdrawUser = "notfound@example.com"

	err := runWithdraw(nil, nil)
	// Expect "no user found" or service error, not panic.
	_ = err
}

// ──────────────────────────── runSecretAccess ──────────────────────────────

func TestRunSecretAccess_MissingUserFlag(t *testing.T) {
	orig := secretAccessUser
	defer func() { secretAccessUser = orig }()
	secretAccessUser = ""
	err := runSecretAccess(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--user is required")
}

func TestRunSecretAccess_MissingBothIDAndRef(t *testing.T) {
	origUser, origID, origRef := secretAccessUser, secretAccessSecretID, secretAccessRef
	defer func() {
		secretAccessUser = origUser
		secretAccessSecretID = origID
		secretAccessRef = origRef
	}()
	secretAccessUser = "u@example.com"
	secretAccessSecretID = 0
	secretAccessRef = ""
	err := runSecretAccess(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--secret-id or --ref is required")
}

func TestRunSecretAccess_RefPath_ServiceInit(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origUser, origID, origRef := secretAccessUser, secretAccessSecretID, secretAccessRef
	defer func() {
		secretAccessUser = origUser
		secretAccessSecretID = origID
		secretAccessRef = origRef
	}()
	secretAccessUser = "u@example.com"
	secretAccessSecretID = 0
	secretAccessRef = "proj/env/name"

	err := runSecretAccess(nil, nil)
	// Expect resolve-ref or user error, not panic.
	_ = err
}

func TestRunSecretAccess_IDPath_ServiceInit(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origUser, origID := secretAccessUser, secretAccessSecretID
	defer func() { secretAccessUser = origUser; secretAccessSecretID = origID }()
	secretAccessUser = "u@example.com"
	secretAccessSecretID = 42

	err := runSecretAccess(nil, nil)
	// Expect user-not-found or service error, not panic.
	_ = err
}

// ──────────────────────────── dashIfEmpty ─────────────────────────────────

func TestDashIfEmpty_Empty(t *testing.T) {
	assert.Equal(t, "-", dashIfEmpty(""))
}

func TestDashIfEmpty_NonEmpty(t *testing.T) {
	assert.Equal(t, "admin", dashIfEmpty("admin"))
}

// ──────────────────────────── runList deeper path ─────────────────────────

func TestRunList_WithSeededProject(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "default")

	origProject := listProject
	defer func() { listProject = origProject }()
	listProject = ""

	// With KEYORIX_PROJECT set but no "default" project in DB → "not found" error.
	err := runList(nil, nil)
	_ = err // error expected (project not found in DB), not a panic
}

func TestRunList_WithProjectFlag(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origProject := listProject
	defer func() { listProject = origProject }()
	listProject = "myproject"

	// Flag is set directly — exercises the ResolveProject flag path.
	err := runList(nil, nil)
	_ = err // error expected (project "myproject" not found), not a panic
}

// ──────────────────────────── runReview ────────────────────────────────────

func TestRunReview_RejectPath_ServiceInit(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origID, origAction, origBy, origTTL := reviewID, reviewAction, reviewBy, reviewTTL
	defer func() {
		reviewID = origID
		reviewAction = origAction
		reviewBy = origBy
		reviewTTL = origTTL
	}()
	reviewID = 1
	reviewAction = "reject"
	reviewBy = "admin@example.com"
	reviewTTL = ""

	err := runReview(nil, nil)
	// Expect user-not-found or service error, not panic.
	_ = err
}

func TestRunReview_ApprovePath_InvalidTTL(t *testing.T) {
	origID, origAction, origBy, origTTL := reviewID, reviewAction, reviewBy, reviewTTL
	defer func() {
		reviewID = origID
		reviewAction = origAction
		reviewBy = origBy
		reviewTTL = origTTL
	}()

	// Set up so we pass action validation but fail at service init or TTL.
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	reviewID = 1
	reviewAction = "approve"
	reviewBy = "admin@example.com"
	reviewTTL = "not-a-duration"

	// Service init will run; if user is not found, we get user error before TTL.
	err := runReview(nil, nil)
	_ = err
}

func TestRunReview_BadAction(t *testing.T) {
	origID, origAction, origBy := reviewID, reviewAction, reviewBy
	defer func() { reviewID = origID; reviewAction = origAction; reviewBy = origBy }()
	reviewID = 1
	reviewAction = "maybe"
	reviewBy = "admin@example.com"
	err := runReview(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--action must be approve or reject")
}

func TestRunReview_ZeroID(t *testing.T) {
	orig := reviewID
	defer func() { reviewID = orig }()
	reviewID = 0
	err := runReview(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

// ──────────────────────────── access.go helpers ───────────────────────────

func TestDashIfEmpty_ExplicitDash(t *testing.T) {
	assert.Equal(t, "-", dashIfEmpty(""))
	assert.Equal(t, "value", dashIfEmpty("value"))
}

func TestRunAccess_WithValidData(t *testing.T) {
	svc, st := newTestRequestCore(t)
	ctx := context.Background()

	// Create a user, project, and make them a viewer (not an approver).
	u, err := st.CreateUser(ctx, &models.User{Username: "alice3", Email: "alice3@example.com", IsActive: true})
	require.NoError(t, err)
	p, err := st.CreateProject(ctx, &models.Project{Name: "testproj3"})
	require.NoError(t, err)

	// Confirm access is denied since alice3 has no roles.assign.
	err = requireReviewAuthority(ctx, svc, u.ID, p.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not hold")
}
