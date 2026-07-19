package core

import (
	"context"
	"fmt"
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

// newHealthTestDB opens a fresh in-memory SQLite DB with all required tables
// migrated. Each call produces a fully isolated database.
func newHealthTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // required for :memory: isolation
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.User{},
		&models.Project{},
		&models.Environment{},
		&models.SecretAccessLog{},
		&models.MachineIdentity{},
		&models.AuditEvent{},
		&models.RotationPolicy{},
		&models.ShareRecord{},
		&models.UserGroup{},
	))
	return db
}

// makeSecret creates a SecretNode in the given project/environment. Pinning a
// recent CreatedAt keeps rotation scores low so tests can be deterministic.
func makeHealthSecret(t *testing.T, c *KeyorixCore, name string, projectID, envID, ownerID uint) uint {
	t.Helper()
	s, err := c.storage.CreateSecret(context.Background(), &models.SecretNode{
		Name:          name,
		ProjectID:     projectID,
		EnvironmentID: envID,
		Type:          "password",
		OwnerID:       ownerID,
		IsSecret:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)
	return s.ID
}

func TestGetProjectHealthSummary_Empty(t *testing.T) {
	db := newHealthTestDB(t)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "empty-project"})
	require.NoError(t, err)

	summary, err := c.GetProjectHealthSummary(ctx, p.ID, 20)
	require.NoError(t, err)
	assert.Equal(t, p.ID, summary.ProjectID)
	assert.Equal(t, 0, summary.TotalSecrets)
	assert.Equal(t, 0, summary.HighRiskCount)
	assert.Equal(t, 0, summary.MediumRiskCount)
	assert.Equal(t, 0, summary.LowRiskCount)
	assert.Empty(t, summary.TopRiskSecrets)
}

func TestGetProjectHealthSummary_Counts(t *testing.T) {
	db := newHealthTestDB(t)
	ctx := context.Background()
	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "counts-project"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)

	// HIGH secret: expired 10d ago + old (400d, never rotated) + no reads + owner only.
	// expiry=100*0.30=30, rotation=100*0.30=30, usage=80*0.20=16, exposure=10*0.20=2 → 78 ≥ 67 → HIGH
	oldCreated := now.AddDate(0, 0, -400)
	expired := now.AddDate(0, 0, -10)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "expired-secret", ProjectID: p.ID, EnvironmentID: e.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		Expiration: &expired,
		CreatedAt:  oldCreated, UpdatedAt: oldCreated,
	})
	require.NoError(t, err)

	// MEDIUM secret: old (400d) but has many reads (usage=10) and no expiry (40) and owner only.
	// expiry=40*0.30=12, rotation=100*0.30=30, usage=10*0.20=2, exposure=10*0.20=2 → 46 → MEDIUM
	medS, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "old-active-secret", ProjectID: p.ID, EnvironmentID: e.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: oldCreated, UpdatedAt: oldCreated,
	})
	require.NoError(t, err)
	for i := 0; i < 12; i++ {
		require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
			SecretNodeID: medS.ID, AccessedBy: "owner", Action: "read", AccessTime: now,
		}))
	}

	// LOW secret: expires far in the future, freshly created, many reads.
	// expiry=10*0.30=3, rotation=10*0.30=3, usage=10*0.20=2, exposure=10*0.20=2 → 10 → LOW
	future := now.AddDate(1, 0, 0)
	lowS, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "fresh-secret", ProjectID: p.ID, EnvironmentID: e.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		Expiration: &future,
		CreatedAt:  now, UpdatedAt: now,
	})
	require.NoError(t, err)
	for i := 0; i < 12; i++ {
		require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
			SecretNodeID: lowS.ID, AccessedBy: "owner", Action: "read", AccessTime: now,
		}))
	}

	summary, err := c.GetProjectHealthSummary(ctx, p.ID, 20)
	require.NoError(t, err)
	assert.Equal(t, 3, summary.TotalSecrets)
	// Band counts must add up to total.
	assert.Equal(t, summary.TotalSecrets, summary.HighRiskCount+summary.MediumRiskCount+summary.LowRiskCount)
	// We expect exactly 1 HIGH, 1 MEDIUM, 1 LOW.
	assert.Equal(t, 1, summary.HighRiskCount, "expired-secret should be HIGH")
	assert.Equal(t, 1, summary.MediumRiskCount, "old-active-secret should be MEDIUM")
	assert.Equal(t, 1, summary.LowRiskCount, "fresh-secret should be LOW")
	// All 3 secrets must appear in TopRiskSecrets (limit=20 > 3).
	assert.Len(t, summary.TopRiskSecrets, 3)
	// Must be sorted descending.
	for i := 1; i < len(summary.TopRiskSecrets); i++ {
		assert.GreaterOrEqual(t, summary.TopRiskSecrets[i-1].Score, summary.TopRiskSecrets[i].Score)
	}
}

func TestGetProjectHealthSummary_Limit(t *testing.T) {
	db := newHealthTestDB(t)
	ctx := context.Background()
	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "limit-project"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)

	// Create 5 secrets.
	for i := 0; i < 5; i++ {
		makeHealthSecret(t, c, fmt.Sprintf("s%d", i), p.ID, e.ID, 1)
	}

	summary, err := c.GetProjectHealthSummary(ctx, p.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, 5, summary.TotalSecrets)
	// Only the top 2 should be returned.
	assert.Len(t, summary.TopRiskSecrets, 2)
	// They must be in descending order.
	require.Equal(t, 2, len(summary.TopRiskSecrets))
	assert.GreaterOrEqual(t, summary.TopRiskSecrets[0].Score, summary.TopRiskSecrets[1].Score)
}

func TestGetProjectHealthSummary_WrongProject(t *testing.T) {
	db := newHealthTestDB(t)
	ctx := context.Background()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}

	// Create two projects; put secrets only in p1.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p1.ID})
	require.NoError(t, err)
	makeHealthSecret(t, c, "only-in-p1", p1.ID, e.ID, 1)

	// Querying p2 must return empty, not p1's secrets.
	summary, err := c.GetProjectHealthSummary(ctx, p2.ID, 20)
	require.NoError(t, err)
	assert.Equal(t, p2.ID, summary.ProjectID)
	assert.Equal(t, 0, summary.TotalSecrets)
	assert.Empty(t, summary.TopRiskSecrets)
}
