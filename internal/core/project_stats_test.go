package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newStatsTestCore returns a KeyorixCore backed by a migrated, isolated
// in-memory SQLite database suitable for project-stats tests.
func newStatsTestCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.User{},
		&models.UserRole{},
		&models.Role{},
		&models.Group{},
		&models.GroupRole{},
		&models.AnomalyAlert{},
		&models.RotationPolicy{},
		&models.SecretAccessLog{},
		&models.MachineIdentity{},
		&models.AuditEvent{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	return c, db
}

// TestGetProjectStats_Empty verifies that a project with no secrets returns
// zero counts.
func TestGetProjectStats_Empty(t *testing.T) {
	c, _ := newStatsTestCore(t)
	ctx := context.Background()

	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "empty-proj"})
	require.NoError(t, err)

	stats, err := c.GetProjectStats(ctx, proj.ID)
	require.NoError(t, err)

	assert.Equal(t, proj.ID, stats.ProjectID)
	assert.Equal(t, "empty-proj", stats.ProjectName)
	assert.Equal(t, 0, stats.TotalSecrets)
	assert.Equal(t, 0, stats.ActiveSecrets)
	assert.Equal(t, 0, stats.ExpiredSecrets)
	assert.Equal(t, 0, stats.ExpiringIn30Days)
	assert.Equal(t, 0, stats.RotationEnabled)
	assert.Equal(t, 0, stats.OverdueRotation)
	assert.Nil(t, stats.LastRotationAt)
	assert.Equal(t, 0, stats.UniqueAccessors)
	assert.Equal(t, 0, stats.OpenAnomalies)
	assert.NotNil(t, stats.ClassificationCounts)
	assert.NotZero(t, stats.ComputedAt)
}

// TestGetProjectStats_SecretCounts seeds 3 active + 1 expired + 1 expiring-soon
// secret and verifies the secret-count breakdown.
func TestGetProjectStats_SecretCounts(t *testing.T) {
	c, _ := newStatsTestCore(t)
	ctx := context.Background()
	now := time.Now()

	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "counts-proj"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)

	mkSecret := func(name string, expiration *time.Time) {
		_, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name:          name,
			ProjectID:     proj.ID,
			EnvironmentID: env.ID,
			Type:          "password",
			IsSecret:      true,
			Expiration:    expiration,
			CreatedAt:     now,
			UpdatedAt:     now,
		})
		require.NoError(t, err)
	}

	// 3 active (no expiration)
	mkSecret("active-1", nil)
	mkSecret("active-2", nil)
	mkSecret("active-3", nil)

	// 1 expired (expiration in the past)
	past := now.Add(-24 * time.Hour)
	mkSecret("expired-1", &past)

	// 1 expiring soon (expiration 10 days from now, inside the 30-day window)
	soon := now.Add(10 * 24 * time.Hour)
	mkSecret("expiring-soon", &soon)

	stats, err := c.GetProjectStats(ctx, proj.ID)
	require.NoError(t, err)

	assert.Equal(t, 5, stats.TotalSecrets)
	assert.Equal(t, 1, stats.ExpiredSecrets)
	assert.Equal(t, 1, stats.ExpiringIn30Days)
	assert.Equal(t, 4, stats.ActiveSecrets, "5 total - 1 expired")
}

// TestGetProjectStats_ClassificationBreakdown seeds secrets with different
// classification labels and verifies the ClassificationCounts map.
func TestGetProjectStats_ClassificationBreakdown(t *testing.T) {
	c, _ := newStatsTestCore(t)
	ctx := context.Background()
	now := time.Now()

	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "classif-proj"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)

	labels := []string{"confidential", "confidential", "internal", "internal", "internal", "public", ""}
	for i, lbl := range labels {
		_, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name:           "sec-" + string(rune('a'+i)),
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			Type:           "password",
			IsSecret:       true,
			Classification: lbl,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
		require.NoError(t, err)
	}

	stats, err := c.GetProjectStats(ctx, proj.ID)
	require.NoError(t, err)

	assert.Equal(t, 2, stats.ClassificationCounts["confidential"])
	assert.Equal(t, 3, stats.ClassificationCounts["internal"])
	assert.Equal(t, 1, stats.ClassificationCounts["public"])
	assert.Equal(t, 1, stats.ClassificationCounts["unclassified"]) // empty label → unclassified
	assert.Equal(t, 7, stats.TotalSecrets)
}

// TestGetProjectStats_RotationHealth seeds secrets with a rotation policy,
// marks one as overdue (last rotated long ago), and verifies rotation counts.
func TestGetProjectStats_RotationHealth(t *testing.T) {
	c, _ := newStatsTestCore(t)
	ctx := context.Background()

	fixed := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }

	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "rotation-proj"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)

	// Create two secrets: one recently rotated (ok), one long-overdue.
	recentRotatedAt := fixed.Add(-5 * 24 * time.Hour)    // 5 days ago
	overdueRotatedAt := fixed.Add(-200 * 24 * time.Hour) // 200 days ago

	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "recent", ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", IsSecret: true,
		LastRotatedAt: &recentRotatedAt,
		CreatedAt:     recentRotatedAt, UpdatedAt: fixed,
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "overdue", ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", IsSecret: true,
		LastRotatedAt: &overdueRotatedAt,
		CreatedAt:     overdueRotatedAt, UpdatedAt: fixed,
	})
	require.NoError(t, err)

	// A 90-day project-scoped rotation policy covering both secrets.
	pID := proj.ID
	require.NoError(t, c.storage.CreateRotationPolicy(ctx, &models.RotationPolicy{
		Name:            "90d policy",
		Scope:           "project",
		ProjectID:       &pID,
		IntervalDays:    90,
		AlertDaysBefore: 7,
		IsActive:        true,
		CreatedBy:       "test",
	}))

	stats, err := c.GetProjectStats(ctx, proj.ID)
	require.NoError(t, err)

	assert.Equal(t, 2, stats.RotationEnabled, "both secrets are covered")
	assert.Equal(t, 1, stats.OverdueRotation, "only the 200-day-old one is overdue")
	require.NotNil(t, stats.LastRotationAt)
	assert.Equal(t, recentRotatedAt.UTC().Truncate(time.Second),
		stats.LastRotationAt.UTC().Truncate(time.Second),
		"LastRotationAt should be the most recent rotation")
}

// TestGetProjectStats_WrongProject verifies that a nonexistent project ID
// returns an error.
func TestGetProjectStats_WrongProject(t *testing.T) {
	c, _ := newStatsTestCore(t)
	ctx := context.Background()

	_, err := c.GetProjectStats(ctx, 99999)
	require.Error(t, err)
}
