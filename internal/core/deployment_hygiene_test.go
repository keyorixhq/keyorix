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

func TestDeploymentHygieneSummary(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{},
		&models.Environment{}, &models.SecretAccessLog{}, &models.MachineIdentity{}, &models.AuditEvent{},
		&models.RotationPolicy{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "leaver", Email: "l@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	// p1 carries debt: one orphaned secret (owner 2 departs) + one expiring secret.
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	soon := now.Add(10 * 24 * time.Hour)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "orphan", ProjectID: p1.ID, EnvironmentID: e1.ID, Type: "password", OwnerID: 2,
		IsSecret: true, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "expiring", ProjectID: p1.ID, EnvironmentID: e1.ID, Type: "password", OwnerID: 1,
		IsSecret: true, Expiration: &soon, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NoError(t, c.storage.DeleteUser(ctx, 2)) // offboard → "orphan" is orphaned

	// p2 is clean: a single secret with a recent read (not unused), live owner, no expiry.
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)
	clean, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "ok", ProjectID: p2.ID, EnvironmentID: e2.ID, Type: "password", OwnerID: 1,
		IsSecret: true, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
		SecretNodeID: clean.ID, AccessedBy: "owner", Action: "read", AccessTime: now,
	}))

	t.Run("totals sum across projects; breakdown lists only projects with debt", func(t *testing.T) {
		h, err := c.DeploymentHygieneSummary(ctx, 90, 30, 90)
		require.NoError(t, err)
		assert.Equal(t, 1, h.Totals.OrphanedSecrets)
		assert.Equal(t, 1, h.Totals.ExpiringSecrets)
		assert.Equal(t, 2, h.Totals.UnusedSecrets, "both p1 secrets are unused; p2's was read")

		require.Len(t, h.Projects, 1, "only p1 has outstanding signals")
		assert.Equal(t, p1.ID, h.Projects[0].ProjectID)
		assert.Equal(t, "p1", h.Projects[0].ProjectName)
		assert.Equal(t, 1, h.Projects[0].OrphanedSecrets)
	})

	t.Run("windows default when non-positive", func(t *testing.T) {
		h, err := c.DeploymentHygieneSummary(ctx, 0, 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 1, h.Totals.OrphanedSecrets)
	})
}
