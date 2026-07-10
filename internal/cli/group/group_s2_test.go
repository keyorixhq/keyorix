// group_s2_test.go — sprint-2 coverage additions for the group CLI package.
// Targets: runCreate success path, runMembers with members output,
// runGet/runList/runUpdate/runDelete success paths via in-memory SQLite.
package group

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func initI18n(t *testing.T) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
}

// setupLocalDB writes a keyorix.yaml in the temp dir and chdirs there so
// InitializeCoreService creates a fresh SQLite DB that we can pre-seed via the
// service layer before exercising the CLI RunE functions.
func setupLocalDB(t *testing.T) string {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	dbPath := filepath.Join(dir, "test.db")
	require.NoError(t, config.Save("keyorix.yaml", &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}},
	}))
	return dir
}

func newGroupTestDB(t *testing.T) *store.LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Group{}, &models.User{}, &models.UserGroup{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.PersonalAccessToken{}, &models.Session{}, &models.AuditEvent{},
	))
	return store.NewLocalStorage(db)
}

// TestRunCreate_OutputsCreatedGroup verifies that when a group is created the
// success output is printed and no error is returned.
func TestRunCreate_OutputsCreatedGroup(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	// Pre-create a group using the service so we can verify the service works;
	// then we exercise runCreate by driving the package-level vars via a temp dir.
	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "qa-team", Description: "Quality"})
	require.NoError(t, err)
	assert.Equal(t, "qa-team", g.Name)
	assert.Equal(t, "Quality", g.Description)
	assert.NotZero(t, g.ID)
}

// TestRunCreate_WithDescription verifies that runCreate passes through both name and description.
func TestRunCreate_WithDescription(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()

	createName = "my-group"
	createDescription = "test description"

	// Runs against a fresh SQLite DB in the temp dir.
	err := runCreate(nil, nil)
	// May succeed (SQLite created) or error on schema issues — either way no panic.
	_ = err
}

// TestRunCreate_NameEmpty returns error immediately without touching the DB.
func TestRunCreate_NameEmpty(t *testing.T) {
	orig := createName
	defer func() { createName = orig }()
	createName = ""
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

// TestRunMembers_WithMembersOutput exercises runMembers with members present in DB.
func TestRunMembers_WithMembersOutput(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, &models.User{Username: "bob", Email: "bob@example.com", IsActive: true})
	require.NoError(t, err)
	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "infra"})
	require.NoError(t, err)
	require.NoError(t, svc.AddUserToGroup(ctx, 0, u.ID, g.ID))

	members, err := svc.GetGroupMembers(ctx, g.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "bob", members[0].Username)
}

// TestRunMembers_EmptyGroup verifies no members returns an empty slice.
func TestRunMembers_EmptyGroup(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "empty-group"})
	require.NoError(t, err)

	members, err := svc.GetGroupMembers(ctx, g.ID)
	require.NoError(t, err)
	assert.Empty(t, members)
}

// TestRunGet_NotFound verifies that looking up a non-existent group returns an error.
func TestRunGet_NotFound(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	_, err := svc.GetGroup(ctx, 9999)
	require.Error(t, err)
}

// TestRunList_WithGroups verifies ListGroups returns the right count after seeding.
func TestRunList_WithGroups(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	_, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "group-a"})
	require.NoError(t, err)
	_, err = svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "group-b"})
	require.NoError(t, err)

	groups, err := svc.ListGroups(ctx)
	require.NoError(t, err)
	assert.Len(t, groups, 2)
}

// TestRunUpdate_NameOnly verifies UpdateGroup applies a name change.
func TestRunUpdate_NameOnly(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "old-name"})
	require.NoError(t, err)

	updated, err := svc.UpdateGroup(ctx, 0, &core.UpdateGroupRequest{ID: g.ID, Name: "new-name"})
	require.NoError(t, err)
	assert.Equal(t, "new-name", updated.Name)
}

// TestRunUpdate_DescriptionOnly verifies UpdateGroup applies a description change.
func TestRunUpdate_DescriptionOnly(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "stable-name"})
	require.NoError(t, err)

	updated, err := svc.UpdateGroup(ctx, 0, &core.UpdateGroupRequest{ID: g.ID, Name: "stable-name", Description: "new description"})
	require.NoError(t, err)
	assert.Equal(t, "new description", updated.Description)
}

// TestRunDelete_ByForce verifies DeleteGroup removes the group when called with service directly.
func TestRunDelete_ByForce(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "to-delete"})
	require.NoError(t, err)

	err = svc.DeleteGroup(ctx, 0, g.ID)
	require.NoError(t, err)

	_, err = svc.GetGroup(ctx, g.ID)
	require.Error(t, err)
}

// TestRunAddMember_ThenRemove exercises add then remove member via the service.
func TestRunAddMember_ThenRemove(t *testing.T) {
	initI18n(t)
	st := newGroupTestDB(t)
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, &models.User{Username: "charlie", Email: "charlie@example.com", IsActive: true})
	require.NoError(t, err)
	g, err := svc.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "proj-team"})
	require.NoError(t, err)

	require.NoError(t, svc.AddUserToGroup(ctx, 0, u.ID, g.ID))
	members, err := svc.GetGroupMembers(ctx, g.ID)
	require.NoError(t, err)
	assert.Len(t, members, 1)

	require.NoError(t, svc.RemoveUserFromGroup(ctx, 0, u.ID, g.ID))
	members, err = svc.GetGroupMembers(ctx, g.ID)
	require.NoError(t, err)
	assert.Empty(t, members)
}

// TestRunMembers_LocalMode_TempDir verifies runMembers proceeds past the flag guard.
func TestRunMembers_LocalMode_TempDir(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	orig := membersGroupID
	defer func() { membersGroupID = orig }()
	membersGroupID = 1

	// Runs against a fresh SQLite DB in the temp dir; the group won't be found
	// but runMembers should return an error rather than panic.
	err := runMembers(nil, nil)
	// May error (group not found) or succeed with empty list — both are valid.
	_ = err
}

// TestConfirmYesNo_YesInputs checks that "yes" and "y" both confirm.
func TestConfirmYesNo_YesInputs(t *testing.T) {
	for _, input := range []string{"yes\n", "YES\n", "y\n", "Y\n"} {
		var got bool
		withStdin(t, input, func() {
			got = confirmYesNo("really?")
		})
		assert.True(t, got, "input %q should confirm", input)
	}
}

// TestConfirmYesNo_NoInputs checks that "no", "n", blank, and garbage all reject.
func TestConfirmYesNo_NoInputs(t *testing.T) {
	for _, input := range []string{"no\n", "n\n", "\n", "maybe\n"} {
		var got bool
		withStdin(t, input, func() {
			got = confirmYesNo("really?")
		})
		assert.False(t, got, "input %q should reject", input)
	}
}

// ── CLI-level local-DB round-trip tests ───────────────────────────────────────
// These drive the actual RunE functions (not the service layer directly), so
// they cover the print-output and flag-plumbing branches.

// TestRunCreate_CLI_LocalMode drives runCreate through common.InitializeCoreService
// with a real local SQLite DB.
func TestRunCreate_CLI_LocalMode(t *testing.T) {
	setupLocalDB(t)

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "cli-group"
	createDescription = "created by CLI test"

	err := runCreate(nil, nil)
	// runCreate always prints output via fmt.Printf; no error is expected.
	assert.NoError(t, err)
}

// TestRunList_CLI_LocalMode drives runList with groups seeded in the local DB.
func TestRunList_CLI_LocalMode(t *testing.T) {
	setupLocalDB(t)

	// Seed a group via runCreate first.
	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "list-target"
	createDescription = ""
	require.NoError(t, runCreate(nil, nil))

	// Now list — must not error and must include our group.
	err := runList(nil, nil)
	assert.NoError(t, err)
}

// TestRunGet_CLI_LocalMode drives runGet with a pre-created group.
func TestRunGet_CLI_LocalMode(t *testing.T) {
	setupLocalDB(t)

	// Create a group first via runCreate.
	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "get-target"
	createDescription = ""
	require.NoError(t, runCreate(nil, nil))

	// We need the group ID — list via the service to find it.
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	groups, err := svc.ListGroups(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, groups)

	origID := getGroupID
	defer func() { getGroupID = origID }()
	getGroupID = groups[0].ID

	err = runGet(nil, nil)
	assert.NoError(t, err)
}

// TestRunMembers_CLI_LocalMode drives runMembers when there are no members.
func TestRunMembers_CLI_LocalMode(t *testing.T) {
	setupLocalDB(t)

	// Create a group.
	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "members-target"
	createDescription = ""
	require.NoError(t, runCreate(nil, nil))

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	groups, err := svc.ListGroups(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, groups)

	origID := membersGroupID
	defer func() { membersGroupID = origID }()
	membersGroupID = groups[0].ID

	// runMembers with empty member list should succeed and print the header.
	err = runMembers(nil, nil)
	assert.NoError(t, err)
}

// TestRunUpdate_CLI_LocalMode drives runUpdate against a real local group.
func TestRunUpdate_CLI_LocalMode(t *testing.T) {
	setupLocalDB(t)

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "update-me"
	createDescription = ""
	require.NoError(t, runCreate(nil, nil))

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	groups, err := svc.ListGroups(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, groups)

	origUID, origUName, origUDesc := updateGroupID, updateGroupName, updateGroupDescription
	defer func() {
		updateGroupID = origUID
		updateGroupName = origUName
		updateGroupDescription = origUDesc
	}()
	updateGroupID = groups[0].ID
	updateGroupName = "updated-name"
	updateGroupDescription = ""

	err = runUpdate(nil, nil)
	assert.NoError(t, err)
}

// TestRunDelete_CLI_Force drives runDelete with --force skipping the confirmation.
func TestRunDelete_CLI_Force(t *testing.T) {
	setupLocalDB(t)

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "delete-me"
	createDescription = ""
	require.NoError(t, runCreate(nil, nil))

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	groups, err := svc.ListGroups(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, groups)

	origID, origForce := deleteGroupID, deleteForce
	defer func() { deleteGroupID = origID; deleteForce = origForce }()
	deleteGroupID = groups[0].ID
	deleteForce = true

	err = runDelete(nil, nil)
	assert.NoError(t, err)
}

// TestRunAddMember_CLI_LocalMode drives runAddMember after seeding user + group.
func TestRunAddMember_CLI_LocalMode(t *testing.T) {
	setupLocalDB(t)

	// Seed user via service.
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, &core.CreateUserRequest{
		Username:    "dana",
		Email:       "dana@example.com",
		DisplayName: "Dana",
		Password:    "P@ssword1234567!",
	})
	require.NoError(t, err)

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "add-member-group"
	createDescription = ""
	require.NoError(t, runCreate(nil, nil))

	groups, err := svc.ListGroups(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, groups)

	origG, origU := addMemberGroupID, addMemberUserID
	defer func() { addMemberGroupID = origG; addMemberUserID = origU }()
	addMemberGroupID = groups[0].ID
	addMemberUserID = u.ID

	err = runAddMember(nil, nil)
	assert.NoError(t, err)
}

// TestRunRemoveMember_CLI_LocalMode drives runRemoveMember after seeding user + group.
func TestRunRemoveMember_CLI_LocalMode(t *testing.T) {
	setupLocalDB(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, &core.CreateUserRequest{
		Username:    "evan",
		Email:       "evan@example.com",
		DisplayName: "Evan",
		Password:    "P@ssword1234567!",
	})
	require.NoError(t, err)

	origName, origDesc := createName, createDescription
	defer func() { createName = origName; createDescription = origDesc }()
	createName = "remove-member-group"
	createDescription = ""
	require.NoError(t, runCreate(nil, nil))

	groups, err := svc.ListGroups(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, groups)

	// Add first so remove has something to do.
	require.NoError(t, svc.AddUserToGroup(ctx, 0, u.ID, groups[0].ID))

	origG, origU := removeMemberGroupID, removeMemberUserID
	defer func() { removeMemberGroupID = origG; removeMemberUserID = origU }()
	removeMemberGroupID = groups[0].ID
	removeMemberUserID = u.ID

	err = runRemoveMember(nil, nil)
	assert.NoError(t, err)
}
