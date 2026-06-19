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

func TestProjectHygieneSummary(t *testing.T) {
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

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)

	mk := func(name string, ownerID uint, exp *time.Time) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: ownerID,
			IsSecret: true, Expiration: exp, CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, err)
		return s.ID
	}

	soon := now.Add(10 * 24 * time.Hour)
	_ = mk("kept", 1, nil)              // not orphaned/expiring; unused (no read)
	_ = mk("orphan", 2, nil)            // orphaned (owner 2 deleted); unused
	_ = mk("expiring", 1, &soon)        // expiring within 30d; unused
	freshID := mk("fresh-read", 1, nil) // has a recent read → not unused

	// A recent read for fresh-read so it is not counted as unused.
	require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
		SecretNodeID: freshID, AccessedBy: "owner", Action: "read", AccessTime: now,
	}))

	// Offboard user 2 so "orphan" is orphaned.
	require.NoError(t, c.storage.DeleteUser(ctx, 2))

	// Machine identities: one stale (active, last seen 200d ago), one fresh.
	old := now.Add(-200 * 24 * time.Hour)
	require.NoError(t, db.Create(&models.MachineIdentity{ProjectID: p.ID, Name: "ci-old", IdentityType: "ci", State: MachineActive, CreatedAt: old, LastSeenAt: &old}).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{ProjectID: p.ID, Name: "ci-new", IdentityType: "ci", State: MachineActive, CreatedAt: now, LastSeenAt: &now}).Error)

	t.Run("counts each hygiene signal independently", func(t *testing.T) {
		h, err := c.ProjectHygieneSummary(ctx, p.ID, 90, 30, 90)
		require.NoError(t, err)
		assert.Equal(t, 1, h.OrphanedSecrets, "only 'orphan' (owner deleted)")
		assert.Equal(t, 1, h.ExpiringSecrets, "only 'expiring' within 30d")
		assert.Equal(t, 1, h.StaleMachineIdentities, "only 'ci-old'")
		assert.Equal(t, 3, h.UnusedSecrets, "kept + orphan + expiring; fresh-read excluded")
		assert.Equal(t, 0, h.RotationOverdue, "no rotation policies yet")
	})

	t.Run("counts secrets overdue for rotation once a policy applies", func(t *testing.T) {
		// A project-scoped policy with a 1-day interval — every secret (all created
		// 'now', none rotated) is past due by the time we look... actually daysSince=0,
		// so make the interval 0 to force overdue, or use an already-old secret.
		require.NoError(t, c.storage.CreateRotationPolicy(ctx, &models.RotationPolicy{
			Name: "30-day", Scope: "project", ProjectID: &p.ID, IntervalDays: 1, AlertDaysBefore: 1,
			IsActive: true, CreatedBy: "owner",
		}))
		old := now.Add(-10 * 24 * time.Hour)
		_, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: "stale-rot", ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1,
			IsSecret: true, CreatedAt: old, UpdatedAt: old,
		})
		require.NoError(t, err)

		h, err := c.ProjectHygieneSummary(ctx, p.ID, 90, 30, 90)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, h.RotationOverdue, 1, "the 10-day-old secret is overdue under a 1-day policy")
	})

	t.Run("a project ID of zero is rejected", func(t *testing.T) {
		_, err := c.ProjectHygieneSummary(ctx, 0, 0, 0, 0)
		require.Error(t, err)
	})

	t.Run("windows default when non-positive", func(t *testing.T) {
		h, err := c.ProjectHygieneSummary(ctx, p.ID, 0, 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 1, h.OrphanedSecrets)
	})
}
