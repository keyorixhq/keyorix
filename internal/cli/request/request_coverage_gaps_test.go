// request_coverage_gaps_test.go — targeted coverage for branches the existing
// suites leave unexercised: the "service init failed" early-return in every
// top-level command that has no injectable service factory (unlike
// bulk.go's bulkInitService), and the genuine storage-error branch of
// Authorize() inside requireListAuthority/requireReviewAuthority/
// requireTemplateAuthority (as opposed to the far more common "resolves but
// isn't authorized" branch, already covered by list_template_authority_test.go
// and review_authority_test.go).
package request

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ── shared fixtures ─────────────────────────────────────────────────────────

// withInvalidStorageConfig points KEYORIX_CONFIG_PATH at a config file with an
// unrecognised storage.type, so common.InitializeCoreService's real
// factory.CreateStorage call fails. This is the only way to exercise the
// "failed to initialize service" branch of access/list/review/secret-access/
// withdraw: unlike bulk.go's bulkInitService, none of those commands have an
// injectable service factory, so the real function must actually fail.
// Mirrors common.TestInitializeCoreService_InvalidStorageTypeFails.
func withInvalidStorageConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	// Isolate HOME/XDG_CONFIG_HOME too: a leftover ~/.keyorix/cli.yaml in client
	// mode on the machine running this test would otherwise still be picked up by
	// common.ResolveRemote before InitializeCoreService's own storage.type check
	// is ever reached, making this "force a local storage-init failure" fixture
	// intermittently take the remote branch instead. Mirrors
	// cli_remote_mode_behavior_test.go's identical isolation for the same reason.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`storage:
  type: "invalid-storage-type"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
}

// usersOnlyCounter avoids DSN collisions across parallel package runs.
var usersOnlyCounter int

// newUsersOnlyCore returns a KeyorixCore backed by an in-memory SQLite DB that
// has ONLY the users table migrated (no role/permission tables at all), with
// one user seeded. Calling Authorize (directly, or via any requireXAuthority
// helper) against this service returns a genuine storage error — not merely
// "no roles held" — because GetUserRoleIDsAt queries a table that doesn't
// exist. This exercises the err!=nil branch of Authorize() that a
// fully-seeded RBAC fixture (newTestRequestCore) can never reach, since every
// role query there just returns an empty/negative result, not an error.
func newUsersOnlyCore(t *testing.T, email string) (*core.KeyorixCore, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	usersOnlyCounter++
	dsn := fmt.Sprintf("file:users_only_%d?mode=memory&cache=shared", usersOnlyCounter)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	u := &models.User{Username: "partial-user", Email: email, IsActive: true}
	require.NoError(t, db.Create(u).Error)
	svc := core.NewKeyorixCore(store.NewLocalStorage(db))
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	})
	return svc, u.ID
}

// ── InitializeCoreService failure paths (no injectable factory) ─────────────

func TestRunAccess_InitServiceError_RealFailure(t *testing.T) {
	withInvalidStorageConfig(t)
	origUser, origProject := accessUser, accessProject
	defer func() { accessUser = origUser; accessProject = origProject }()
	accessUser = "user@example.com"
	// A project must be supplied so ResolveProject succeeds and control reaches
	// InitializeCoreService -- the branch this test exercises. ResolveProject now
	// runs before the remote/local branch decision (both paths need the resolved
	// project name), so an unset --project would surface "no project specified"
	// before ever reaching storage init.
	accessProject = "irrelevant"

	err := runAccess(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
	assert.Contains(t, err.Error(), "failed to create storage")
}

func TestRunList_InitServiceError_RealFailure(t *testing.T) {
	withInvalidStorageConfig(t)
	origProject := listProject
	defer func() { listProject = origProject }()
	// Same reason as TestRunAccess_InitServiceError_RealFailure above.
	listProject = "irrelevant"

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
	assert.Contains(t, err.Error(), "failed to create storage")
}

func TestRunReview_InitServiceError_RealFailure(t *testing.T) {
	withInvalidStorageConfig(t)
	origID, origAction := reviewID, reviewAction
	defer func() { reviewID = origID; reviewAction = origAction }()
	reviewID = 1
	reviewAction = "approve"

	err := runReview(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
	assert.Contains(t, err.Error(), "failed to create storage")
}

func TestRunSecretAccess_InitServiceError_RealFailure(t *testing.T) {
	withInvalidStorageConfig(t)
	origUser, origID := secretAccessUser, secretAccessSecretID
	defer func() { secretAccessUser = origUser; secretAccessSecretID = origID }()
	secretAccessUser = "user@example.com"
	secretAccessSecretID = 1

	err := runSecretAccess(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
	assert.Contains(t, err.Error(), "failed to create storage")
}

func TestRunWithdraw_InitServiceError_RealFailure(t *testing.T) {
	withInvalidStorageConfig(t)
	origID := withdrawID
	defer func() { withdrawID = origID }()
	withdrawID = 1

	err := runWithdraw(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
	assert.Contains(t, err.Error(), "failed to create storage")
}

// ── runList: remaining branches ──────────────────────────────────────────────

// TestRunList_ResolveProjectError exercises the common.ResolveProject error
// branch: no --project flag, no KEYORIX_PROJECT, and no active project on
// disk leaves nothing for runList to resolve.
func TestRunList_ResolveProjectError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Isolate HOME/XDG_CONFIG_HOME too: a leftover ~/.keyorix/cli.yaml in client
	// mode on the machine running this test would otherwise still be picked up by
	// common.ResolveRemote, making this "run in embedded/local mode" test
	// intermittently take the remote branch instead. Mirrors
	// cli_remote_mode_behavior_test.go's identical isolation for the same reason.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "")
	// #G-blank-storage-default: runList's InitializeCoreService call now hard-errors
	// on a blank storage.type instead of silently defaulting to local storage — write
	// an explicit config so the test still reaches the "no project specified" branch
	// this test is targeting, rather than failing earlier on storage init.
	writeLocalStorageConfig(t)

	origProject := listProject
	defer func() { listProject = origProject }()
	listProject = ""

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no project specified")
}

// TestRunList_ResolveUserIDError exercises the resolveUserID error branch:
// --by names an email with no matching user record.
func TestRunList_ResolveUserIDError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Isolate HOME/XDG_CONFIG_HOME too: a leftover ~/.keyorix/cli.yaml in client
	// mode on the machine running this test would otherwise still be picked up by
	// common.ResolveRemote, making this "run in embedded/local mode" test
	// intermittently take the remote branch instead. Mirrors
	// cli_remote_mode_behavior_test.go's identical isolation for the same reason.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedRequestDB(t)

	origProject, origBy := listProject, listBy
	defer func() { listProject = origProject; listBy = origBy }()
	listProject = "testproj"
	listBy = "nobody-at-all@example.com"

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no user found")
}

// TestRunList_RequireListAuthorityError exercises the
// "requireListAuthority returns an error" branch via the real runList
// entrypoint: --by resolves to a real user who simply doesn't hold
// roles.assign at the project.
func TestRunList_RequireListAuthorityError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Isolate HOME/XDG_CONFIG_HOME too: a leftover ~/.keyorix/cli.yaml in client
	// mode on the machine running this test would otherwise still be picked up by
	// common.ResolveRemote, making this "run in embedded/local mode" test
	// intermittently take the remote branch instead. Mirrors
	// cli_remote_mode_behavior_test.go's identical isolation for the same reason.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, projectID, svc := seedRequestDB(t)
	ctx := context.Background()
	unprivileged, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "list-unpriv", Email: "list-unpriv@example.com", IsActive: true,
	})
	require.NoError(t, err)
	_ = projectID

	origProject, origBy := listProject, listBy
	defer func() { listProject = origProject; listBy = origBy }()
	listProject = "testproj"
	listBy = unprivileged.Email

	runErr := runList(nil, nil)
	require.Error(t, runErr)
	assert.Contains(t, runErr.Error(), "roles.assign")
}

// ── Authorize() genuine storage-error branch (direct helper calls) ──────────

// TestRequireListAuthority_AuthorizeStorageError exercises the err!=nil
// branch inside requireListAuthority's call to svc.Authorize — distinct from
// the far more common "resolves but isn't authorized" (ok=false) branch
// already covered by TestRequireListAuthority_UnprivilegedActorRejected.
func TestRequireListAuthority_AuthorizeStorageError(t *testing.T) {
	svc, uid := newUsersOnlyCore(t, "partial-list@example.com")
	err := requireListAuthority(context.Background(), svc, uid, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
}

// TestRequireReviewAuthority_AuthorizeStorageError is the review.go sibling
// of the above.
func TestRequireReviewAuthority_AuthorizeStorageError(t *testing.T) {
	svc, uid := newUsersOnlyCore(t, "partial-review@example.com")
	err := requireReviewAuthority(context.Background(), svc, uid, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
}

// TestRequireTemplateAuthority_AuthorizeStorageError is the bulk.go sibling.
func TestRequireTemplateAuthority_AuthorizeStorageError(t *testing.T) {
	svc, uid := newUsersOnlyCore(t, "partial-tmpl@example.com")
	err := requireTemplateAuthority(context.Background(), svc, uid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
}

// ── bulk.go: requireTemplateAuthority error propagation from each caller ────

// TestRunTmplList_RequireTemplateAuthorityError exercises runTmplList's own
// "if err := requireTemplateAuthority(...); err != nil" branch (as opposed to
// the "not ok" case already covered indirectly): the --by user resolves, but
// the underlying Authorize call itself fails closed on missing role tables.
func TestRunTmplList_RequireTemplateAuthorityError(t *testing.T) {
	origBy := tmplListBy
	defer func() { tmplListBy = origBy }()
	tmplListBy = "partial-list-cmd@example.com"
	withUserSeededPartialService(t, "partial-list-cmd@example.com")

	err := runTmplList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
}

// TestRunTmplAdd_RequireTemplateAuthorityError is runTmplAdd's sibling.
func TestRunTmplAdd_RequireTemplateAuthorityError(t *testing.T) {
	origName, origReason, origBy := tmplName, tmplReason, tmplBy
	defer func() { tmplName = origName; tmplReason = origReason; tmplBy = origBy }()
	tmplName = "x"
	tmplReason = "y"
	tmplBy = "partial-add-cmd@example.com"
	withUserSeededPartialService(t, "partial-add-cmd@example.com")

	err := runTmplAdd(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
}

// TestRunTmplDelete_RequireTemplateAuthorityError is runTmplDelete's sibling.
func TestRunTmplDelete_RequireTemplateAuthorityError(t *testing.T) {
	origBy := tmplDeleteBy
	defer func() { tmplDeleteBy = origBy }()
	tmplDeleteBy = "partial-delete-cmd@example.com"
	withUserSeededPartialService(t, "partial-delete-cmd@example.com")

	err := runTmplDelete(nil, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
}

// TestRunTmplDelete_DeleteTemplateNotFoundError exercises runTmplDelete's
// DeleteRejectionReasonTemplate error branch specifically — an authorized
// admin (so requireTemplateAuthority passes) deleting an ID that was never
// created.
func TestRunTmplDelete_DeleteTemplateNotFoundError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Isolate HOME/XDG_CONFIG_HOME too: a leftover ~/.keyorix/cli.yaml in client
	// mode on the machine running this test would otherwise still be picked up by
	// common.ResolveRemote, making this "run in embedded/local mode" test
	// intermittently take the remote branch instead. Mirrors
	// cli_remote_mode_behavior_test.go's identical isolation for the same reason.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedBulkApproveDB(t)

	origBy := tmplDeleteBy
	defer func() { tmplDeleteBy = origBy }()
	tmplDeleteBy = "admin@example.com"

	err := runTmplDelete(nil, []string{"99999"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete template")
}
