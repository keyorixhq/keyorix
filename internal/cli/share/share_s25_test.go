// share_s25_test.go – coverage push for cli/share: fills the remaining ~10% gap
// by exercising:
//   - runCreate with an absolute --expires (user and group share paths)
//   - runCreate service-error wrapping ("failed to share secret with user/group")
//   - runRevoke service-error wrapping ("failed to revoke share")
//   - runUpdate service-error wrapping ("failed to update share permission")
//   - runList / runSharedSecrets remote-error propagation through the top-level
//     dispatch functions (not just the inner runListRemote / runSharedSecretsRemote helpers)
//   - command registration: groupSharesCmd and selfRemoveCmd in ShareCmd
package share

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── runCreate – absolute --expires path ─────────────

// TestRunCreate_WithExpires_UserShare exercises the absolute-RFC3339 --expires
// branch in runCreate for a user share (createIsGroup=false, createExpires set).
func TestRunCreate_WithExpires_UserShare(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	ownerID, secretID, projID := seedShareData(t, svc)

	ctx := context.Background()
	recipient, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "exptgt", Email: "exptgt@example.com", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, svc.AddProjectMember(ctx, ownerID, projID, recipient.ID, "project_viewer"))

	origSecretID, origRecipientID, origPerm, origIsGroup, origExpires :=
		createSecretID, createRecipientID, createPermission, createIsGroup, createExpires
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
		createExpires = origExpires
	}()
	createSecretID = secretID
	createRecipientID = recipient.ID
	createPermission = "read"
	createIsGroup = false
	createExpires = "2040-01-01T00:00:00Z"

	require.NoError(t, runCreate(nil, nil))
}

// TestRunCreate_WithExpires_GroupShare exercises the absolute-RFC3339 --expires
// branch in runCreate for a group share (createIsGroup=true, createExpires set).
func TestRunCreate_WithExpires_GroupShare(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	svc := openShareCore(t)
	_, secretID, _ := seedShareData(t, svc)

	ctx := context.Background()
	grp, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "expires-grp"})
	require.NoError(t, err)

	origSecretID, origRecipientID, origPerm, origIsGroup, origExpires :=
		createSecretID, createRecipientID, createPermission, createIsGroup, createExpires
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
		createExpires = origExpires
	}()
	createSecretID = secretID
	createRecipientID = grp.ID
	createPermission = "write"
	createIsGroup = true
	createExpires = "2040-06-01T12:00:00Z"

	require.NoError(t, runCreate(nil, nil))
}

// ──────────────────────────── runCreate – service error wrapping ──────────────

// TestRunCreate_UserShare_ServiceError verifies that a core-layer failure is
// wrapped with "failed to share secret with user".
func TestRunCreate_UserShare_ServiceError(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// openShareCore so storage is initialised (so InitializeStorage inside
	// runCreate succeeds), but we pass a secretID that does not exist so
	// ShareSecret returns an error.
	_ = openShareCore(t)

	origSecretID, origRecipientID, origPerm, origIsGroup :=
		createSecretID, createRecipientID, createPermission, createIsGroup
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
	}()
	createSecretID = 99999 // does not exist
	createRecipientID = 1
	createPermission = "read"
	createIsGroup = false

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to share secret with user")
}

// TestRunCreate_GroupShare_ServiceError verifies that a core-layer failure for a
// group share is wrapped with "failed to share secret with group".
func TestRunCreate_GroupShare_ServiceError(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_ = openShareCore(t)

	origSecretID, origRecipientID, origPerm, origIsGroup :=
		createSecretID, createRecipientID, createPermission, createIsGroup
	defer func() {
		createSecretID = origSecretID
		createRecipientID = origRecipientID
		createPermission = origPerm
		createIsGroup = origIsGroup
	}()
	createSecretID = 99999 // does not exist
	createRecipientID = 1
	createPermission = "write"
	createIsGroup = true

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to share secret with group")
}

// ──────────────────────────── runRevoke – service error wrapping ──────────────

// TestRunRevoke_ServiceError_WrapsMessage verifies that when RevokeShare fails
// the error is wrapped with "failed to revoke share".
func TestRunRevoke_ServiceError_WrapsMessage(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// Initialise storage so InitializeStorage inside runRevoke succeeds, then
	// request revocation of a share that does not exist.
	_ = openShareCore(t)

	orig := revokeShareID
	defer func() { revokeShareID = orig }()
	revokeShareID = 88888 // does not exist

	err := runRevoke(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke share")
}

// ──────────────────────────── runUpdate – service error wrapping ──────────────

// TestRunUpdate_ServiceError_WrapsMessage verifies that when UpdateSharePermission
// fails the error is wrapped with "failed to update share permission".
func TestRunUpdate_ServiceError_WrapsMessage(t *testing.T) {
	dir := t.TempDir()
	writeShareTestConfig(t, dir)
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_ = openShareCore(t)

	origID, origPerm := updateShareID, updatePermission
	defer func() { updateShareID = origID; updatePermission = origPerm }()
	updateShareID = 77777 // does not exist
	updatePermission = "write"

	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update share permission")
}

// ──────────────────────────── runList remote error propagation ───────────────

// TestRunList_Remote_PropagatesError verifies that when the remote server returns
// an error, runList (the top-level dispatch) propagates it — not just runListRemote.
func TestRunList_Remote_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origID := listSecretID
	defer func() { listSecretID = origID }()
	listSecretID = 3

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list shares")
}

// ──────────────────────────── runSharedSecrets remote error propagation ───────

// TestRunSharedSecrets_Remote_PropagatesError verifies that when the remote server
// returns an error, runSharedSecrets (the top-level dispatch) propagates it.
func TestRunSharedSecrets_Remote_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := runSharedSecrets(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list shared secrets")
}

// ──────────────────────────── command registration ───────────────────────────

// TestGroupSharesCmd_RegisteredInShareCmd verifies that group-shares is
// registered as a subcommand of the top-level share command.
func TestGroupSharesCmd_RegisteredInShareCmd(t *testing.T) {
	found := false
	for _, sub := range ShareCmd.Commands() {
		if sub.Use == groupSharesCmd.Use {
			found = true
			break
		}
	}
	assert.True(t, found, "groupSharesCmd should be registered under ShareCmd")
}

// TestSelfRemoveCmd_RegisteredInShareCmd verifies that self-remove is registered
// as a subcommand of the top-level share command.
func TestSelfRemoveCmd_RegisteredInShareCmd(t *testing.T) {
	found := false
	for _, sub := range ShareCmd.Commands() {
		if sub.Use == selfRemoveCmd.Use {
			found = true
			break
		}
	}
	assert.True(t, found, "selfRemoveCmd should be registered under ShareCmd")
}
