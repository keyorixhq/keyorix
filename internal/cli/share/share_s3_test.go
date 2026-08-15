// share_s3_test.go – coverage push for cli/share: exercises the local-storage
// success paths (print-table output) that the s2/remote test files leave at
// <30%.
//
// Strategy:
//  1. Write a minimal keyorix.yaml to the test's temp dir (so config.Load("")
//     finds it and InitializeStorage uses a SQLite file inside the same dir).
//  2. Open a second connection via the factory and seed the database with the
//     objects the command under test needs.
//  3. Run the command function directly — it opens its own connection to the
//     same SQLite file, so it sees the seeded data and executes the full
//     happy-path (including the tabwriter print block).
package share

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeShareTestConfig writes a minimal keyorix.yaml in the given directory
// that points SQLite storage at "<dir>/share_test.db".
func writeShareTestConfig(t *testing.T, dir string) {
	t.Helper()
	dbPath := filepath.Join(dir, "share_test.db")
	yaml := fmt.Sprintf(`locale:
  language: en
  fallback_language: en
storage:
  database:
    path: %q
  encryption:
    enabled: false
security:
  enable_file_permission_check: false
  allow_unsafe_file_permissions: true
`, dbPath)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0o600))
}

// openShareCore opens the same storage backend that the commands will use in
// the given directory (t.Chdir must be called first so config.Load finds the yaml).
func openShareCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.NoError(t, i18n.Initialize(cfg))
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	return core.NewKeyorixCore(st)
}

// seedShareData seeds a user, project, environment, and secret needed by the
// share commands and returns ownerID, secretID, and projID.
func seedShareData(t *testing.T, svc *core.KeyorixCore) (ownerID, secretID, projID uint) {
	t.Helper()
	ctx := context.Background()

	svc.SetBootstrapToken("share-s3-token")
	_, err := svc.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "owner", Email: "owner@example.com",
		Password: "BootstrapPass123!", DisplayName: "Owner",
		Token: "share-s3-token",
	})
	require.NoError(t, err)

	u, err := svc.GetUserByEmail(ctx, "owner@example.com")
	require.NoError(t, err)
	ownerID = u.ID

	proj, err := svc.CreateProject(ctx, "shareproj", "")
	require.NoError(t, err)
	projID = proj.ID

	// CreateProject seeds default environments; fetch the first one.
	envs, err := svc.Storage().ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "default environments should be seeded")

	secret, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "api-key",
		Value:         []byte("s3cret"),
		Type:          "password",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "owner",
		OwnerID:       ownerID,
	})
	require.NoError(t, err)
	secretID = secret.ID
	return
}

// ──────────────────────────── runCreate ────────────────────────────────────

// TestRunCreate_UserShare_Success exercises the user-share happy path through
// the tabwriter print block.
func TestRunCreate_UserShare_Success(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", ownerID)) // #G67: runCreate now asserts SharedBy from this

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "recipient", Email: "recipient@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	origSecretID, origRecipientID, origPerm, origIsGroup :=
		createSecretID, createRecipientID, createPermission, createIsGroup
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
	}()
	createSecretID = secretID
	createRecipientID = recipient.ID
	createPermission = "read"
	createIsGroup = false

	require.NoError(t, runCreate(nil, nil))
}

// TestRunCreate_GroupShare_Success exercises the group-share happy path.
func TestRunCreate_GroupShare_Success(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, _ := seedShareData(t, svc)
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", ownerID)) // #G67: runCreate now asserts SharedBy from this

	ctx := context.Background()
	grp, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "teamalpha"})
	require.NoError(t, err)

	origSecretID, origRecipientID, origPerm, origIsGroup :=
		createSecretID, createRecipientID, createPermission, createIsGroup
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
	}()
	createSecretID = secretID
	createRecipientID = grp.ID
	createPermission = "write"
	createIsGroup = true

	require.NoError(t, runCreate(nil, nil))
}

// TestRunCreate_WithTTL_Success exercises the TTL path in runCreate.
func TestRunCreate_WithTTL_Success(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", ownerID)) // #G67: runCreate now asserts SharedBy from this

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "recv2", Email: "recv2@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	origSecretID, origRecipientID, origPerm, origIsGroup, origTTL :=
		createSecretID, createRecipientID, createPermission, createIsGroup, createTTL
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
		createTTL = origTTL
	}()
	createSecretID = secretID
	createRecipientID = recipient.ID
	createPermission = "read"
	createIsGroup = false
	createTTL = "24h"

	require.NoError(t, runCreate(nil, nil))
}

// ──────────────────────────── runList (local) ──────────────────────────────

// TestRunList_PrintsTableForExistingShares exercises the tabwriter output path.
func TestRunList_PrintsTableForExistingShares(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "listtgt", Email: "listtgt@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	_, err = svc.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: secretID, RecipientID: recipient.ID,
		Permission: "read", SharedBy: ownerID,
	})
	require.NoError(t, err)

	orig := listSecretID
	defer func() { listSecretID = orig }()
	listSecretID = secretID

	require.NoError(t, runList(nil, nil))
}

// TestRunList_PrintsTableWithExpiry exercises the expiry column in tabwriter.
func TestRunList_PrintsTableWithExpiry(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "listtgt2", Email: "listtgt2@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	exp := time.Now().Add(48 * time.Hour)
	_, err = svc.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: secretID, RecipientID: recipient.ID,
		Permission: "write", SharedBy: ownerID, ExpiresAt: &exp,
	})
	require.NoError(t, err)

	orig := listSecretID
	defer func() { listSecretID = orig }()
	listSecretID = secretID

	require.NoError(t, runList(nil, nil))
}

// ──────────────────────────── runRevoke ────────────────────────────────────

// TestRunRevoke_Success exercises the full revoke path including success print.
func TestRunRevoke_Success(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", ownerID)) // #G67: runRevoke now asserts revokedBy from this

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "revoketgt", Email: "revoketgt@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	share, err := svc.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: secretID, RecipientID: recipient.ID,
		Permission: "read", SharedBy: ownerID,
	})
	require.NoError(t, err)

	orig := revokeShareID
	defer func() { revokeShareID = orig }()
	revokeShareID = share.ID

	require.NoError(t, runRevoke(nil, nil))
}

// ──────────────────────────── runGroupShares ───────────────────────────────

// TestRunGroupShares_PrintsTable exercises the tabwriter path when group shares
// exist.
func TestRunGroupShares_PrintsTable(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, _ := seedShareData(t, svc)

	ctx := context.Background()
	grp, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "devteam"})
	require.NoError(t, err)

	_, err = svc.ShareSecretWithGroup(ctx, &core.GroupShareSecretRequest{
		SecretID:   secretID,
		GroupID:    grp.ID,
		Permission: "read",
		SharedBy:   ownerID,
	})
	require.NoError(t, err)

	orig := groupSharesGroupID
	defer func() { groupSharesGroupID = orig }()
	groupSharesGroupID = grp.ID

	// #G10: ListGroupShares now self-authorizes (secrets.read); the embedded/local CLI
	// has no authenticated session, so it self-asserts an actor via KEYORIX_CLI_ACTOR
	// (common.ResolveActorID, #150) — here, the bootstrap admin.
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", ownerID))

	require.NoError(t, runGroupShares(nil, nil))
}

// ──────────────────────────── runSharedSecrets (local) ─────────────────────

// TestRunSharedSecrets_PrintsTable exercises the tabwriter output path.
func TestRunSharedSecrets_PrintsTable(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "sharedtgt", Email: "sharedtgt@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	_, err = svc.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: secretID, RecipientID: recipient.ID,
		Permission: "read", SharedBy: ownerID,
	})
	require.NoError(t, err)

	orig := sharedSecretsUserID
	defer func() { sharedSecretsUserID = orig }()
	sharedSecretsUserID = recipient.ID

	require.NoError(t, runSharedSecrets(nil, nil))
}

// ──────────────────────────── runUpdate ────────────────────────────────────

// TestRunUpdate_Success exercises the full update-permission happy path.
func TestRunUpdate_Success(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", ownerID)) // #G67: runUpdate now asserts updatedBy from this

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "updatetgt", Email: "updatetgt@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	share, err := svc.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: secretID, RecipientID: recipient.ID,
		Permission: "read", SharedBy: ownerID,
	})
	require.NoError(t, err)

	origID, origPerm, origClear := updateShareID, updatePermission, updateClearExpiry
	defer func() {
		updateShareID = origID
		updatePermission = origPerm
		updateClearExpiry = origClear
	}()
	updateShareID = share.ID
	updatePermission = "write"
	updateClearExpiry = false

	require.NoError(t, runUpdate(nil, nil))
}

// TestRunUpdate_WithTTL_Success exercises the expiry-setting update path.
func TestRunUpdate_WithTTL_Success(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", ownerID)) // #G67: runUpdate now asserts updatedBy from this

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "updatetgt2", Email: "updatetgt2@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	share, err := svc.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: secretID, RecipientID: recipient.ID,
		Permission: "read", SharedBy: ownerID,
	})
	require.NoError(t, err)

	origID, origPerm, origTTL := updateShareID, updatePermission, updateTTL
	defer func() {
		updateShareID = origID
		updatePermission = origPerm
		updateTTL = origTTL
	}()
	updateShareID = share.ID
	updatePermission = "write"
	updateTTL = "48h"

	require.NoError(t, runUpdate(nil, nil))
}

// TestRunUpdate_ClearExpiry_Success exercises the ClearExpiry flag path.
func TestRunUpdate_ClearExpiry_Success(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", ownerID)) // #G67: runUpdate now asserts updatedBy from this

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "clearexptgt", Email: "clearexptgt@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	exp := time.Now().Add(24 * time.Hour)
	share, err := svc.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: secretID, RecipientID: recipient.ID,
		Permission: "write", SharedBy: ownerID, ExpiresAt: &exp,
	})
	require.NoError(t, err)

	origID, origPerm, origClear := updateShareID, updatePermission, updateClearExpiry
	defer func() {
		updateShareID = origID
		updatePermission = origPerm
		updateClearExpiry = origClear
	}()
	updateShareID = share.ID
	updatePermission = "read"
	updateClearExpiry = true

	require.NoError(t, runUpdate(nil, nil))
}

// ──────────────────────────── remote error paths ───────────────────────────

// TestRunListRemote_ServerError covers the HTTP error branch of runListRemote.
func TestRunListRemote_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	err := runListRemote(rc, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list shares")
}

// TestRunSharedSecretsRemote_ServerError covers the HTTP error branch.
func TestRunSharedSecretsRemote_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	err := runSharedSecretsRemote(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list shared secrets")
}

// TestRunSharedSecretsRemote_WithData exercises the print path of runSharedSecretsRemote.
func TestRunSharedSecretsRemote_WithData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secrets":[
			{"ID":3,"Name":"db-pass","Type":"password","ProjectID":1,"EnvironmentID":2,"CreatedBy":"admin","CreatedAt":"2026-01-01T00:00:00Z"}
		]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	require.NoError(t, runSharedSecretsRemote(rc))
}

// TestRunUpdate_BadExpires covers the --expires validation path in runUpdate.
func TestRunUpdate_BadExpires(t *testing.T) {
	origPerm, origID, origExpires := updatePermission, updateShareID, updateExpires
	defer func() { updatePermission = origPerm; updateShareID = origID; updateExpires = origExpires }()
	updatePermission = "read"
	updateShareID = 1
	updateExpires = "not-a-date"

	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--expires")
}

// TestRunUpdate_BadTTL covers the --ttl validation path in runUpdate.
func TestRunUpdate_BadTTL(t *testing.T) {
	origPerm, origID, origTTL := updatePermission, updateShareID, updateTTL
	defer func() { updatePermission = origPerm; updateShareID = origID; updateTTL = origTTL }()
	updatePermission = "write"
	updateShareID = 1
	updateTTL = "not-a-duration"

	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ttl")
}
