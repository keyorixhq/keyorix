// groups_membership_s38_test.go — coverage top-up for groups.go membership
// functions. Targets branches not yet exercised by groups_audit_test.go and
// authz_admin_ceiling_group_test.go:
//   - AddUserToGroup: zero userID or groupID returns validation error
//   - RemoveUserFromGroup: zero userID or groupID returns validation error
//   - GetGroupMembers: groupID == 0 returns validation error
//   - GetGroupMembers: happy path returns members
//   - GetGroup: ID == 0 returns validation error
//   - ListGroups: returns all groups
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newGroupsS38Core returns a KeyorixCore backed by an isolated in-memory SQLite
// DB with all tables needed for group membership tests.
func newGroupsS38Core(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Role{},
		&models.User{}, &models.UserRole{}, &models.AuditEvent{},
	))
	return &KeyorixCore{storage: store.NewLocalStorage(db)}, db
}

// ── AddUserToGroup validation ─────────────────────────────────────────────────

// TestAddUserToGroup_ZeroUserID verifies a zero userID is rejected.
func TestAddUserToGroup_ZeroUserID(t *testing.T) {
	c, db := newGroupsS38Core(t)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "dev"}).Error)
	err := c.AddUserToGroupGlobal(context.Background(), 1, 0, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestAddUserToGroup_ZeroGroupID verifies a zero groupID is rejected.
func TestAddUserToGroup_ZeroGroupID(t *testing.T) {
	c, db := newGroupsS38Core(t)
	require.NoError(t, db.Create(&models.User{ID: 7, Username: "bob", Email: "bob@example.com"}).Error)
	err := c.AddUserToGroupGlobal(context.Background(), 1, 7, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestAddUserToGroup_CLIActor_ZeroActorID verifies the CLI actor (actorID=0) path
// bypasses role-check and succeeds when user+group are valid.
func TestAddUserToGroup_CLIActor_ZeroActorID(t *testing.T) {
	c, db := newGroupsS38Core(t)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "cli-group"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 20, Username: "cli-user", Email: "cli@example.com"}).Error)
	err := c.AddUserToGroupGlobal(context.Background(), 0, 20, 10)
	require.NoError(t, err)
}

// ── RemoveUserFromGroup validation ────────────────────────────────────────────

// TestRemoveUserFromGroup_ZeroUserID verifies a zero userID is rejected.
func TestRemoveUserFromGroup_ZeroUserID(t *testing.T) {
	c, db := newGroupsS38Core(t)
	require.NoError(t, db.Create(&models.Group{ID: 15, Name: "ops"}).Error)
	err := c.RemoveUserFromGroupGlobal(context.Background(), 1, 0, 15)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestRemoveUserFromGroup_ZeroGroupID verifies a zero groupID is rejected.
func TestRemoveUserFromGroup_ZeroGroupID(t *testing.T) {
	c, db := newGroupsS38Core(t)
	require.NoError(t, db.Create(&models.User{ID: 25, Username: "alice", Email: "alice@example.com"}).Error)
	err := c.RemoveUserFromGroupGlobal(context.Background(), 1, 25, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// ── GetGroupMembers ───────────────────────────────────────────────────────────

// TestGetGroupMembers_ZeroGroupID verifies a zero groupID returns a validation error.
func TestGetGroupMembers_ZeroGroupID(t *testing.T) {
	c, _ := newGroupsS38Core(t)
	_, err := c.GetGroupMembers(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestGetGroupMembers_HappyPath verifies GetGroupMembers returns the correct members.
func TestGetGroupMembers_HappyPath(t *testing.T) {
	c, db := newGroupsS38Core(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Group{ID: 30, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 40, Username: "member1", Email: "m1@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 41, Username: "member2", Email: "m2@example.com"}).Error)

	// Add members directly via store (bypasses guard that checks last admin).
	require.NoError(t, c.AddUserToGroupGlobal(ctx, 0, 40, 30))
	require.NoError(t, c.AddUserToGroupGlobal(ctx, 0, 41, 30))

	members, err := c.GetGroupMembers(ctx, 30)
	require.NoError(t, err)
	require.Len(t, members, 2)
	ids := make([]uint, 0, 2)
	for _, m := range members {
		ids = append(ids, m.ID)
	}
	assert.ElementsMatch(t, []uint{40, 41}, ids)
}

// ── GetGroup ──────────────────────────────────────────────────────────────────

// TestGetGroup_ZeroID verifies a zero ID returns a validation error.
func TestGetGroup_ZeroID(t *testing.T) {
	c, _ := newGroupsS38Core(t)
	_, err := c.GetGroup(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// ── ListGroups ────────────────────────────────────────────────────────────────

// TestListGroups_ReturnsAll verifies that ListGroups returns all created groups.
func TestListGroups_ReturnsAll(t *testing.T) {
	c, db := newGroupsS38Core(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Group{ID: 50, Name: "alpha"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 51, Name: "beta"}).Error)

	groups, err := c.ListGroups(ctx)
	require.NoError(t, err)
	assert.Len(t, groups, 2)
}
