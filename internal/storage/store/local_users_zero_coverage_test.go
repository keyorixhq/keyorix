// local_users_zero_coverage_test.go covers local_users.go functions that
// were still at 0%: ListInactiveUsers, GetUserGroupsAt, ListGroupMembersAt.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newUsersZeroCoverageStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Group{}, &models.UserGroup{}))
	return NewLocalStorage(db)
}

func TestListInactiveUsers(t *testing.T) {
	ls := newUsersZeroCoverageStore(t)
	db := ls.DB()

	threshold := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	oldLogin := threshold.Add(-48 * time.Hour)
	recentLogin := threshold.Add(48 * time.Hour)
	oldCreated := threshold.Add(-72 * time.Hour)

	// Inactive: last login before threshold.
	require.NoError(t, db.Create(&models.User{Username: "u1", UsernameFolded: "u1", Email: "u1@x.io", EmailFolded: "u1@x.io", LastLoginAt: &oldLogin}).Error)
	// Active: last login after threshold.
	require.NoError(t, db.Create(&models.User{Username: "u2", UsernameFolded: "u2", Email: "u2@x.io", EmailFolded: "u2@x.io", LastLoginAt: &recentLogin}).Error)
	// Never logged in, created before threshold -- inactive.
	u3 := &models.User{Username: "u3", UsernameFolded: "u3", Email: "u3@x.io", EmailFolded: "u3@x.io"}
	require.NoError(t, db.Create(u3).Error)
	require.NoError(t, db.Model(u3).Update("created_at", oldCreated).Error)
	// Never logged in, created after threshold -- active (too new to judge).
	require.NoError(t, db.Create(&models.User{Username: "u4", UsernameFolded: "u4", Email: "u4@x.io", EmailFolded: "u4@x.io"}).Error)

	users, err := ls.ListInactiveUsers(context.Background(), threshold)
	require.NoError(t, err)
	names := map[string]bool{}
	for _, u := range users {
		names[u.Username] = true
	}
	assert.True(t, names["u1"])
	assert.False(t, names["u2"])
	assert.True(t, names["u3"])
	assert.False(t, names["u4"])
}

func TestGetUserGroupsAt(t *testing.T) {
	ls := newUsersZeroCoverageStore(t)
	ctx := context.Background()
	db := ls.DB()

	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "global-group", NameFolded: "global-group"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 2, Name: "proj7-group", NameFolded: "proj7-group"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 3, Name: "proj8-group", NameFolded: "proj8-group"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 10, GroupID: 1, ProjectID: 0}).Error) // global
	require.NoError(t, db.Create(&models.UserGroup{UserID: 10, GroupID: 2, ProjectID: 7}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 10, GroupID: 3, ProjectID: 8}).Error)

	groups, err := ls.GetUserGroupsAt(ctx, 10, storage.Scope{ProjectID: 7})
	require.NoError(t, err)
	ids := map[uint]bool{}
	for _, g := range groups {
		ids[g.ID] = true
	}
	assert.True(t, ids[1], "a global (project_id=0) membership must always be included")
	assert.True(t, ids[2], "the project-7-scoped membership must be included at scope project 7")
	assert.False(t, ids[3], "a different project's scoped membership must be excluded")
}

func TestListGroupMembersAt(t *testing.T) {
	ls := newUsersZeroCoverageStore(t)
	ctx := context.Background()
	db := ls.DB()

	require.NoError(t, db.Create(&models.User{ID: 20, Username: "member-global", UsernameFolded: "member-global", Email: "mg@x.io", EmailFolded: "mg@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 21, Username: "member-proj7", UsernameFolded: "member-proj7", Email: "mp7@x.io", EmailFolded: "mp7@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 22, Username: "member-proj8", UsernameFolded: "member-proj8", Email: "mp8@x.io", EmailFolded: "mp8@x.io"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 20, GroupID: 5, ProjectID: 0}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 21, GroupID: 5, ProjectID: 7}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 22, GroupID: 5, ProjectID: 8}).Error)

	users, err := ls.ListGroupMembersAt(ctx, 5, storage.Scope{ProjectID: 7})
	require.NoError(t, err)
	ids := map[uint]bool{}
	for _, u := range users {
		ids[u.ID] = true
	}
	assert.True(t, ids[20], "a global member must always be included")
	assert.True(t, ids[21])
	assert.False(t, ids[22], "a member scoped to a different project must be excluded")
}
