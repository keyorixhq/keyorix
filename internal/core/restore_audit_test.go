package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Restore operations must be audited (the inverse of the delete events), so a
// soft-deleted secret/project/environment reappearing leaves a trail.
func TestRestoreOperationsAudit(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	auditActor := func(eventType string) *uint {
		var ev models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", eventType).First(&ev).Error, "expected a %s event", eventType)
		return ev.UserID
	}

	t.Run("secret.restored", func(t *testing.T) {
		// A live parent project + environment: RestoreSecret refuses to restore into a
		// soft-deleted parent, so the audit test needs them present and live.
		require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: 999, ProjectID: 1, Name: "env"}).Error)
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "k", ProjectID: 1, EnvironmentID: 999, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
		require.NoError(t, err)
		require.NoError(t, c.storage.DeleteSecret(ctx, s.ID))
		require.NoError(t, c.RestoreSecret(ctx, 42, s.ID))
		require.NotNil(t, auditActor("secret.restored"))
		assert.Equal(t, uint(42), *auditActor("secret.restored"))
	})

	t.Run("project.restored", func(t *testing.T) {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: "proj"})
		require.NoError(t, err)
		require.NoError(t, c.storage.DeleteProject(ctx, p.ID))
		require.NoError(t, c.RestoreProject(ctx, 42, p.ID))
		require.NotNil(t, auditActor("project.restored"))
	})

	t.Run("environment.restored", func(t *testing.T) {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: "proj2"})
		require.NoError(t, err)
		e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
		require.NoError(t, err)
		require.NoError(t, c.storage.DeleteEnvironment(ctx, e.ID))
		require.NoError(t, c.RestoreEnvironment(ctx, 42, p.ID, e.ID))
		require.NotNil(t, auditActor("environment.restored"))
	})
}
