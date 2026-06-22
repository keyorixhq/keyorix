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
		&models.Group{}, &models.GroupRole{}, &models.UserGroup{}, &models.AuditEvent{},
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
