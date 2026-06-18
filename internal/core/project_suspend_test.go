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

func TestSuspendResumeProjectSecrets(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	// Two projects, each with an environment (the secret list query joins environments).
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)

	// Project p1: three secrets (one already suspended). Project p2: one (must be untouched).
	mk := func(name string, projectID, envID uint, status string) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: envID, Type: "password", OwnerID: 1, IsSecret: true,
			Status: status, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}
	mk("a", p1.ID, e1.ID, SecretStatusActive)
	mk("b", p1.ID, e1.ID, SecretStatusActive)
	mk("c", p1.ID, e1.ID, SecretStatusSuspended) // already suspended
	otherID := mk("z", p2.ID, e2.ID, SecretStatusActive)

	t.Run("suspend-all suspends only the active secrets in the project", func(t *testing.T) {
		n, err := c.SuspendProjectSecrets(ctx, p1.ID, 1, "breach")
		require.NoError(t, err)
		assert.Equal(t, 2, n, "the already-suspended one is skipped")

		// Project 2's secret is untouched.
		other, _ := c.storage.GetSecret(ctx, otherID)
		assert.Equal(t, SecretStatusActive, other.Status)
	})

	t.Run("resume-all resumes every suspended secret in the project", func(t *testing.T) {
		n, err := c.ResumeProjectSecrets(ctx, p1.ID, 1)
		require.NoError(t, err)
		assert.Equal(t, 3, n, "all three (now suspended) are resumed")

		// A second resume is a no-op.
		n, err = c.ResumeProjectSecrets(ctx, p1.ID, 1)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("validates ids", func(t *testing.T) {
		_, err := c.SuspendProjectSecrets(ctx, 0, 1, "")
		require.Error(t, err)
		_, err = c.ResumeProjectSecrets(ctx, 1, 0)
		require.Error(t, err)
	})
}
