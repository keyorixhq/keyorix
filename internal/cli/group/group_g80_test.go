// group_g80_test.go — closes the remaining coverage gap on top of
// group_s2_test.go/group_s24_test.go: the local-mode (non-remote) execution
// paths of add-member/remove-member, the "failed to initialize service"
// branch shared by every subcommand, and the remote Post/Delete error
// branches of add-member/remove-member.
//
// A note on isolateFromStaleGlobalConfig: on a developer machine that has
// ever run `keyorix connect`, ~/.keyorix/cli.yaml (or
// $XDG_CONFIG_HOME/keyorix/cli.yaml) can point at a real remote server.
// common.NewRemoteClient() consults that file even when the test only sets
// KEYORIX_SERVER="" — so without isolating $HOME, a test that intends to
// exercise the LOCAL (embedded core) branch can silently flip to the remote
// HTTP branch instead depending on what's installed on the machine running
// it (see internal/cli group_remote_test.go's long comment on this same
// class of issue, and the "Local-only test failures" memory entry). Pointing
// $HOME at a fresh empty temp dir makes these tests deterministic regardless
// of the host machine's state.
package group

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// isolateFromStaleGlobalConfig points $HOME (and clears $XDG_CONFIG_HOME) at a
// fresh, empty temp dir so common.ResolveRemote()/NewRemoteClient() cannot pick
// up a real operator's leftover ~/.keyorix/cli.yaml. See file header comment.
func isolateFromStaleGlobalConfig(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
}

// setupInvalidStorageConfig writes a keyorix.yaml with an unrecognized
// storage.type so common.InitializeCoreService's factory.CreateStorage call
// fails deterministically and fast (no DB I/O, no filesystem-permission
// tricks), letting us drive every subcommand's "failed to initialize
// service" branch reliably.
func setupInvalidStorageConfig(t *testing.T) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, config.Save("keyorix.yaml", &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "not-a-real-backend"},
	}))
}

// ── service-init-error branch: every subcommand ────────────────────────────

func TestRunCreate_ServiceInitError_InvalidStorageType(t *testing.T) {
	setupInvalidStorageConfig(t)

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "whatever"
	createDescription = ""

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunGet_ServiceInitError_InvalidStorageType(t *testing.T) {
	setupInvalidStorageConfig(t)

	orig := getGroupID
	defer func() { getGroupID = orig }()
	getGroupID = 1

	err := runGet(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunList_ServiceInitError_InvalidStorageType(t *testing.T) {
	setupInvalidStorageConfig(t)

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunUpdate_ServiceInitError_InvalidStorageType(t *testing.T) {
	setupInvalidStorageConfig(t)

	origID, origName := updateGroupID, updateGroupName
	defer func() { updateGroupID = origID; updateGroupName = origName }()
	updateGroupID = 1
	updateGroupName = "new-name"

	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunDelete_ServiceInitError_InvalidStorageType(t *testing.T) {
	setupInvalidStorageConfig(t)

	origID, origForce := deleteGroupID, deleteForce
	defer func() { deleteGroupID = origID; deleteForce = origForce }()
	deleteGroupID = 1
	// service init happens before the confirmation prompt in runDelete, but set
	// --force anyway so this test can never block on stdin.
	deleteForce = true

	err := runDelete(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunMembers_ServiceInitError_InvalidStorageType(t *testing.T) {
	setupInvalidStorageConfig(t)

	orig := membersGroupID
	defer func() { membersGroupID = orig }()
	membersGroupID = 1

	err := runMembers(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunAddMember_Local_ServiceInitError_InvalidStorageType(t *testing.T) {
	isolateFromStaleGlobalConfig(t)
	setupInvalidStorageConfig(t)

	origG, origU := addMemberGroupID, addMemberUserID
	defer func() { addMemberGroupID = origG; addMemberUserID = origU }()
	addMemberGroupID = 1
	addMemberUserID = 1

	err := runAddMember(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunRemoveMember_Local_ServiceInitError_InvalidStorageType(t *testing.T) {
	isolateFromStaleGlobalConfig(t)
	setupInvalidStorageConfig(t)

	origG, origU := removeMemberGroupID, removeMemberUserID
	defer func() { removeMemberGroupID = origG; removeMemberUserID = origU }()
	removeMemberGroupID = 1
	removeMemberUserID = 1

	err := runRemoveMember(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// ── add-member / remove-member: local (embedded core) success + error ──────

// TestRunAddMember_Local_Success_Isolated drives the local-mode success branch
// of runAddMember end to end (real seeded user+group, real membership write)
// with $HOME isolated so the test is not at the mercy of the running
// machine's global CLI config.
func TestRunAddMember_Local_Success_Isolated(t *testing.T) {
	isolateFromStaleGlobalConfig(t)
	setupLocalDB(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, &core.CreateUserRequest{
		Username: "kara", Email: "kara@example.com", DisplayName: "Kara",
		Password: "P@ssword1234567!",
	})
	require.NoError(t, err)
	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "isolated-add-group"})
	require.NoError(t, err)

	origG, origU, origP := addMemberGroupID, addMemberUserID, addMemberProjectID
	defer func() {
		addMemberGroupID = origG
		addMemberUserID = origU
		addMemberProjectID = origP
	}()
	addMemberGroupID = g.ID
	addMemberUserID = u.ID
	addMemberProjectID = 0

	err = runAddMember(nil, nil)
	require.NoError(t, err, "local-mode add-member must succeed against a real seeded user+group")

	members, err := svc.GetGroupMembers(ctx, g.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, u.ID, members[0].ID)
}

// TestRunAddMember_Local_ErrorFromService_Isolated drives the local-mode error
// branch deterministically: AddUserToGroup looks the group up before writing
// the membership row, so a nonexistent group ID always errors.
func TestRunAddMember_Local_ErrorFromService_Isolated(t *testing.T) {
	isolateFromStaleGlobalConfig(t)
	setupLocalDB(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, &core.CreateUserRequest{
		Username: "liam", Email: "liam@example.com", DisplayName: "Liam",
		Password: "P@ssword1234567!",
	})
	require.NoError(t, err)

	origG, origU := addMemberGroupID, addMemberUserID
	defer func() { addMemberGroupID = origG; addMemberUserID = origU }()
	addMemberGroupID = 999999 // does not exist
	addMemberUserID = u.ID

	err = runAddMember(nil, nil)
	require.Error(t, err, "adding a member to a nonexistent group must fail, not silently succeed")
	assert.Contains(t, err.Error(), "failed to add member")
}

// TestRunRemoveMember_Local_Success_Isolated drives the local-mode success
// branch of runRemoveMember end to end.
func TestRunRemoveMember_Local_Success_Isolated(t *testing.T) {
	isolateFromStaleGlobalConfig(t)
	setupLocalDB(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, &core.CreateUserRequest{
		Username: "mia", Email: "mia@example.com", DisplayName: "Mia",
		Password: "P@ssword1234567!",
	})
	require.NoError(t, err)
	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "isolated-remove-group"})
	require.NoError(t, err)
	require.NoError(t, svc.AddUserToGroup(ctx, 0, u.ID, g.ID, 0))

	origG, origU := removeMemberGroupID, removeMemberUserID
	defer func() { removeMemberGroupID = origG; removeMemberUserID = origU }()
	removeMemberGroupID = g.ID
	removeMemberUserID = u.ID

	err = runRemoveMember(nil, nil)
	require.NoError(t, err)

	members, err := svc.GetGroupMembers(ctx, g.ID)
	require.NoError(t, err)
	assert.Empty(t, members)
}

// TestRunRemoveMember_Local_RefusesLastGlobalAdmin_Isolated drives the
// local-mode error branch of runRemoveMember deterministically via the same
// last-global-admin guard internal/core/group_admin_guard_test.go exercises
// directly: a group that carries the install's only global "admin" role
// grant, with the target user as its sole member. There is no CLI surface to
// assign a role to a group, so the grant is seeded directly at the storage
// layer against the same sqlite file runRemoveMember will open.
func TestRunRemoveMember_Local_RefusesLastGlobalAdmin_Isolated(t *testing.T) {
	isolateFromStaleGlobalConfig(t)
	dir := setupLocalDB(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, &core.CreateUserRequest{
		Username: "nora", Email: "nora@example.com", DisplayName: "Nora",
		Password: "P@ssword1234567!",
	})
	require.NoError(t, err)
	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "sole-admin-group"})
	require.NoError(t, err)
	require.NoError(t, svc.AddUserToGroup(ctx, 0, u.ID, g.ID, 0))

	dbPath := filepath.Join(dir, "test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.Role{Name: "admin"}).Error)
	var role models.Role
	require.NoError(t, db.Where("name = ?", "admin").First(&role).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: g.ID, RoleID: role.ID}).Error)

	origG, origU := removeMemberGroupID, removeMemberUserID
	defer func() { removeMemberGroupID = origG; removeMemberUserID = origU }()
	removeMemberGroupID = g.ID
	removeMemberUserID = u.ID

	err = runRemoveMember(nil, nil)
	require.Error(t, err, "removing the sole member of the install's only admin-conferring group must be refused")
	assert.Contains(t, err.Error(), "failed to remove member")

	// The membership must survive the refused removal.
	members, merr := svc.GetGroupMembers(ctx, g.ID)
	require.NoError(t, merr)
	require.Len(t, members, 1)
}

// ── add-member / remove-member: remote HTTP error branch ───────────────────

func TestRunAddMember_Remote_PostError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origG, origU := addMemberGroupID, addMemberUserID
	defer func() { addMemberGroupID = origG; addMemberUserID = origU }()
	addMemberGroupID = 7
	addMemberUserID = 3

	err := runAddMember(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add member")
}

func TestRunRemoveMember_Remote_DeleteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origG, origU := removeMemberGroupID, removeMemberUserID
	defer func() { removeMemberGroupID = origG; removeMemberUserID = origU }()
	removeMemberGroupID = 7
	removeMemberUserID = 3

	err := runRemoveMember(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove member")
}

// TestRunAddMember_Remote_PostError_RequestReachesServer verifies that the
// POST error branch is reached only after the request is actually issued
// (not e.g. a client-construction failure) by decoding the captured body.
func TestRunAddMember_Remote_PostError_RequestReachesServer(t *testing.T) {
	reached := false
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origG, origU := addMemberGroupID, addMemberUserID
	defer func() { addMemberGroupID = origG; addMemberUserID = origU }()
	addMemberGroupID = 11
	addMemberUserID = 22

	err := runAddMember(nil, nil)
	require.Error(t, err)
	assert.True(t, reached, "runAddMember must actually issue the POST before surfacing the error")
	require.NotNil(t, body)
	assert.Equal(t, float64(22), body["user_id"])
}
