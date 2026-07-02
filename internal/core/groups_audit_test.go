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

// Group CRUD must be audited (create/update/delete), like other governance
// mutations — previously these wrote nothing on the API/CLI path.
func TestGroupCRUDAudit(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Group{}, &models.GroupRole{}, &models.UserGroup{}, &models.AuditEvent{}, &models.Role{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	ctx := context.Background()

	lastActor := func(eventType string) (int64, *uint) {
		var ev models.AuditEvent
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
		_ = db.Where("event_type = ?", eventType).Order("id DESC").First(&ev).Error
		return n, ev.UserID
	}

	g, err := c.CreateGroup(ctx, 42, &CreateGroupRequest{Name: "ops-team", Description: "ops"})
	require.NoError(t, err)
	n, actor := lastActor(EventGroupCreated)
	assert.Equal(t, int64(1), n)
	require.NotNil(t, actor)
	assert.Equal(t, uint(42), *actor, "the acting admin is recorded")

	_, err = c.UpdateGroup(ctx, 42, &UpdateGroupRequest{ID: g.ID, Description: "platform ops"})
	require.NoError(t, err)
	n, _ = lastActor(EventGroupUpdated)
	assert.Equal(t, int64(1), n)

	require.NoError(t, c.DeleteGroup(ctx, 42, g.ID))
	n, _ = lastActor(EventGroupDeleted)
	assert.Equal(t, int64(1), n)

	require.NoError(t, c.RestoreGroup(ctx, 42, g.ID))
	n, actor = lastActor(EventGroupRestored)
	assert.Equal(t, int64(1), n)
	require.NotNil(t, actor)
	assert.Equal(t, uint(42), *actor)
	// The restored group is retrievable again.
	restored, err := c.GetGroup(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, g.ID, restored.ID)
}

// Group membership (add/remove) is role-grant-equivalent — a member inherits every
// role the group holds — so it must land in the RBAC audit trail (#233), the same
// as a direct /user-roles grant.
func TestGroupMembershipAudit(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Group{}, &models.User{}, &models.UserGroup{}, &models.AuditEvent{},
	))
	require.NoError(t, db.Create(&models.Group{ID: 7, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 11, Username: "alice", Email: "alice@example.com"}).Error)
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	ctx := context.Background()

	require.NoError(t, c.AddUserToGroup(ctx, 42, 11, 7))

	entries, total, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, entries, 1)
	assert.Equal(t, EventGroupMemberAdded, entries[0].Action)
	require.NotNil(t, entries[0].ActorUserID)
	assert.Equal(t, uint(42), *entries[0].ActorUserID)
	require.NotNil(t, entries[0].TargetUserID)
	assert.Equal(t, uint(11), *entries[0].TargetUserID)
	require.NotNil(t, entries[0].GroupID)
	assert.Equal(t, uint(7), *entries[0].GroupID)

	require.NoError(t, c.RemoveUserFromGroup(ctx, 42, 11, 7))

	entries, total, err = c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	var removed *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventGroupMemberRemoved {
			removed = e
		}
	}
	require.NotNil(t, removed, "expected a group.member_removed entry")
	require.NotNil(t, removed.ActorUserID)
	assert.Equal(t, uint(42), *removed.ActorUserID)
	require.NotNil(t, removed.TargetUserID)
	assert.Equal(t, uint(11), *removed.TargetUserID)
	require.NotNil(t, removed.GroupID)
	assert.Equal(t, uint(7), *removed.GroupID)
}

// A CLI invocation (actorID 0) still audits, with no actor recorded.
func TestGroupCreateAudit_UnauthenticatedActor(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Group{}, &models.AuditEvent{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}

	_, err = c.CreateGroup(context.Background(), 0, &CreateGroupRequest{Name: "cli-group"})
	require.NoError(t, err)

	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventGroupCreated).First(&ev).Error)
	assert.Nil(t, ev.UserID, "actorID 0 records no actor")
}
