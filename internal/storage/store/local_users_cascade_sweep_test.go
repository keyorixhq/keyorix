// local_users_cascade_sweep_test.go — partial-coverage sweep for local_users.go:
// genuine duplicate-email branches (unlike the analogous project-name case, SQLite
// DOES name the email_folded column in its constraint-violation text, so these are
// real, reachable branches — see isDuplicateEmailViolation's doc comment), plus
// DB-error paths reached via newBrokenDB or the dropTableAfterQueries technique
// from local_secrets_cascade_sweep_test.go (same package, reused here).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newUsersDBWithEmailIndex migrates User and creates the same partial unique
// index migrateDatabase creates in production (uniq_users_email_folded_active),
// so a genuine duplicate-email insert/update produces the real SQLite
// constraint-violation text isDuplicateEmailViolation matches against.
func newUsersDBWithEmailIndex(t *testing.T) *LocalStorage {
	t.Helper()
	ls := newPartialSecretsDB(t, &models.User{})
	require.NoError(t, ls.db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_folded_active ON users(email_folded) WHERE deleted_at IS NULL AND email != ''").Error)
	return ls
}

func TestCreateUser_DuplicateEmail(t *testing.T) {
	t.Parallel()
	ls := newUsersDBWithEmailIndex(t)
	ctx := context.Background()

	_, err := ls.CreateUser(ctx, &models.User{
		Username: "alice", UsernameFolded: "alice", Email: "Alice@Example.com", EmailFolded: "alice@example.com",
	})
	require.NoError(t, err)

	_, err = ls.CreateUser(ctx, &models.User{
		Username: "alice2", UsernameFolded: "alice2", Email: "ALICE@example.com", EmailFolded: "alice@example.com",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
}

func TestCreateUserWithRoleGrants_DuplicateEmail(t *testing.T) {
	t.Parallel()
	ls := newUsersDBWithEmailIndex(t)
	ctx := context.Background()

	_, err := ls.CreateUser(ctx, &models.User{
		Username: "bob", UsernameFolded: "bob", Email: "bob@example.com", EmailFolded: "bob@example.com",
	})
	require.NoError(t, err)

	_, err = ls.CreateUserWithRoleGrants(ctx, &models.User{
		Username: "bob2", UsernameFolded: "bob2", Email: "bob@example.com", EmailFolded: "bob@example.com",
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
}

func TestUpdateUser_DuplicateEmail(t *testing.T) {
	t.Parallel()
	ls := newUsersDBWithEmailIndex(t)
	ctx := context.Background()

	u1, err := ls.CreateUser(ctx, &models.User{
		Username: "carl", UsernameFolded: "carl", Email: "carl@example.com", EmailFolded: "carl@example.com",
	})
	require.NoError(t, err)
	u2, err := ls.CreateUser(ctx, &models.User{
		Username: "dave", UsernameFolded: "dave", Email: "dave@example.com", EmailFolded: "dave@example.com",
	})
	require.NoError(t, err)

	u2.EmailFolded = u1.EmailFolded
	_, err = ls.UpdateUser(ctx, u2)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
}

func TestUpdateUserIfActiveStateMatches_DuplicateEmail(t *testing.T) {
	t.Parallel()
	ls := newUsersDBWithEmailIndex(t)
	ctx := context.Background()

	u1, err := ls.CreateUser(ctx, &models.User{
		Username: "erin", UsernameFolded: "erin", Email: "erin@example.com", EmailFolded: "erin@example.com", IsActive: true,
	})
	require.NoError(t, err)
	u2, err := ls.CreateUser(ctx, &models.User{
		Username: "finn", UsernameFolded: "finn", Email: "finn@example.com", EmailFolded: "finn@example.com", IsActive: true,
	})
	require.NoError(t, err)

	u2.EmailFolded = u1.EmailFolded
	_, err = ls.UpdateUserIfActiveStateMatches(ctx, u2, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
}

func TestUpdateUserIfActiveStateMatches_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.UpdateUserIfActiveStateMatches(context.Background(), &models.User{ID: 1}, true)
	require.Error(t, err)
	assert.NotErrorIs(t, err, storage.ErrDuplicateEmail)
}

func TestGetUserByEmail_InvalidFold(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetUserByEmail(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrUserNotFound)
}

func TestGetUserByUsername_InvalidFold(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetUserByUsername(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrUserNotFound)
}

func TestGetUserGroupsAt_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetUserGroupsAt(context.Background(), 1, storage.Scope{ProjectID: 1})
	require.Error(t, err)
}

func TestListAllUserGroupMemberships_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListAllUserGroupMemberships(context.Background())
	require.Error(t, err)
}

func TestListInactiveUsers_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListInactiveUsers(context.Background(), time.Now())
	require.Error(t, err)
}

func TestListUsers_FindErrorAfterCountSucceeds(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.User{})
	dropTableAfterQueries(t, ls.db, 1, "users")

	_, _, err := ls.ListUsers(context.Background(), &storage.UserFilter{})
	require.Error(t, err)
}

func TestDeleteGroup_DeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Group{})
	ctx := context.Background()
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "g-delete-fail", NameFolded: "g-delete-fail"})
	require.NoError(t, err)

	dropTableAfterQueries(t, ls.db, 1, "groups")

	err = ls.DeleteGroup(ctx, g.ID)
	require.Error(t, err)
}

func TestDeleteGroup_RowsAffectedZero(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Group{})
	ctx := context.Background()
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "g-race", NameFolded: "g-race"})
	require.NoError(t, err)

	// Race: soft-delete the row via a raw statement right after GetGroup's own
	// read succeeds, so the subsequent GORM soft-delete Update (scoped to
	// deleted_at IS NULL) matches zero rows.
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("race-soft-delete-group", func(_ *gorm.DB) {
		// Use the outer ls.db handle, not the callback's tx: calling
		// Exec on tx mid-callback reuses/pollutes the in-flight SELECT's
		// bound Statement.Vars and silently matches zero rows.
		ls.db.Exec("UPDATE groups SET deleted_at = ? WHERE id = ?", time.Now(), g.ID)
	}))

	err = ls.DeleteGroup(ctx, g.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GroupNotFound")
}

func TestListGroupsPage_FindErrorAfterCountSucceeds(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Group{})
	dropTableAfterQueries(t, ls.db, 1, "groups")

	_, _, err := ls.ListGroupsPage(context.Background(), 0, 10)
	require.Error(t, err)
}

func TestAddUserToGroup_MembershipLookupGenericError(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.User{}, &models.Group{})
	ctx := context.Background()
	u, err := ls.CreateUser(ctx, &models.User{Username: "gu", UsernameFolded: "gu", EmailFolded: "gu@example.com"})
	require.NoError(t, err)
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "gg", NameFolded: "gg"})
	require.NoError(t, err)

	// user_groups table intentionally absent: the membership lookup fails with
	// something other than gorm.ErrRecordNotFound.
	err = ls.AddUserToGroup(ctx, u.ID, g.ID, 0)
	require.Error(t, err)
}

func TestAddUserToGroup_CreateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.User{}, &models.Group{}, &models.UserGroup{})
	ctx := context.Background()
	u, err := ls.CreateUser(ctx, &models.User{Username: "hu", UsernameFolded: "hu", EmailFolded: "hu@example.com"})
	require.NoError(t, err)
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "hg", NameFolded: "hg"})
	require.NoError(t, err)

	// 3 query-family statements precede the Create: GetUser's First, GetGroup's
	// First, and the membership-existence First (not-found). Drop user_groups
	// right after so the Create fails.
	dropTableAfterQueries(t, ls.db, 3, "user_groups")

	err = ls.AddUserToGroup(ctx, u.ID, g.ID, 2)
	require.Error(t, err)
}

func TestListGroupMembers_FindErrorAfterGetGroupSucceeds(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Group{})
	ctx := context.Background()
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "member-fail", NameFolded: "member-fail"})
	require.NoError(t, err)

	// users/user_groups tables intentionally absent.
	_, err = ls.ListGroupMembers(ctx, g.ID)
	require.Error(t, err)
}

func TestListGroupMembersAt_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListGroupMembersAt(context.Background(), 1, storage.Scope{ProjectID: 1})
	require.Error(t, err)
}

func TestPrunePasswordHistory_DeleteFailsAfterPluckSucceeds(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.PasswordHistory{})
	ctx := context.Background()
	require.NoError(t, ls.AddPasswordHistory(ctx, 1, "$2a$10$abc", time.Now()))

	dropTableAfterQueries(t, ls.db, 1, "password_histories")

	err := ls.PrunePasswordHistory(ctx, 1, 1)
	require.Error(t, err)
}
