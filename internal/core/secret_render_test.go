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

// newRenderFixture builds an in-memory core with a project, a "production"
// environment, and a secret "db-password"=s3cr3t owned by user 1.
func newRenderFixture(t *testing.T) (*KeyorixCore, *gorm.DB, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{},
		&models.Project{}, &models.Environment{}, &models.SecretAccessLog{}, &models.AuditEvent{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@test.com"}).Error)

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t"),
	})
	require.NoError(t, err)
	return c, db, proj.ID
}

func TestRenderSecretTemplate(t *testing.T) {
	ctx := context.Background()
	c, _, projectID := newRenderFixture(t)

	t.Run("expands a known reference", func(t *testing.T) {
		out, err := c.RenderSecretTemplate(ctx, "DB=${secret:production/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
		require.NoError(t, err)
		assert.Equal(t, "DB=s3cr3t", out)
	})

	t.Run("unknown environment fails", func(t *testing.T) {
		_, err := c.RenderSecretTemplate(ctx, "${secret:staging/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "environment")
	})

	t.Run("unknown secret fails", func(t *testing.T) {
		_, err := c.RenderSecretTemplate(ctx, "${secret:production/nope}", projectID, 1, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("non-reader cannot resolve", func(t *testing.T) {
		// User 2 owns nothing and has no share → the per-secret read check denies.
		_, err := c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 2, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
	})

	t.Run("requires project + user", func(t *testing.T) {
		_, err := c.RenderSecretTemplate(ctx, "x", 0, 1, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
		_, err = c.RenderSecretTemplate(ctx, "x", projectID, 0, "owner", "10.0.0.1", "ua")
		require.Error(t, err)
	})
}

// A render records a secret read (access log) for each resolved reference, so a bulk
// render can't be a covert exfiltration channel invisible to the audit trail and the
// anomaly detector (which feeds on SecretAccessLog).
func TestRenderSecretTemplate_RecordsReads(t *testing.T) {
	ctx := context.Background()
	c, db, projectID := newRenderFixture(t)

	_, err := c.RenderSecretTemplate(ctx, "DB=${secret:production/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err)

	// The read is logged in a detached goroutine — poll briefly for the access-log row.
	var n int64
	for i := 0; i < 200; i++ {
		require.NoError(t, db.Model(&models.SecretAccessLog{}).Where("accessed_by = ?", "owner").Count(&n).Error)
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.Positive(t, n, "a resolved render reference must produce a secret access-log row")
}

// #180 (secondary): referencing the SAME secret twice in one template must resolve and
// charge max_reads only ONCE — not once per occurrence. A MaxReads=1 secret referenced
// twice would fail on the second occurrence without memoization; with it, the second
// occurrence reuses the first resolution's value and never re-decrements the quota.
func TestRenderSecretTemplate_SameReferenceTwiceChargesMaxReadsOnce(t *testing.T) {
	ctx := context.Background()
	c, db, projectID := newRenderFixture(t)

	one := 1
	require.NoError(t, db.Model(&models.SecretNode{}).Where("name = ?", "db-password").Update("max_reads", &one).Error)

	out, err := c.RenderSecretTemplate(ctx,
		"A=${secret:production/db-password} B=${secret:production/db-password}",
		projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err, "a MaxReads=1 secret referenced twice in one template must not exhaust its quota on the second occurrence")
	assert.Equal(t, "A=s3cr3t B=s3cr3t", out)

	// A third, later render must now be refused — max_reads was charged exactly once,
	// not twice, by the render above.
	_, err = c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 1, "owner", "10.0.0.1", "ua")
	require.Error(t, err, "the quota was already spent by the single charge in the prior render")
}

// #180 (secondary): the access-log/audit record for a repeated reference is written only
// once per distinct reference, not once per occurrence.
func TestRenderSecretTemplate_SameReferenceTwiceLogsOnce(t *testing.T) {
	ctx := context.Background()
	c, db, projectID := newRenderFixture(t)

	_, err := c.RenderSecretTemplate(ctx,
		"A=${secret:production/db-password} B=${secret:production/db-password} C=${secret:production/db-password}",
		projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err)

	// Reads are logged in a detached goroutine — poll briefly, then assert the count
	// settles at exactly one row (not three).
	var n int64
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		require.NoError(t, db.Model(&models.SecretAccessLog{}).Where("accessed_by = ?", "owner").Count(&n).Error)
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let any (incorrect) extra async writes land before asserting
	require.NoError(t, db.Model(&models.SecretAccessLog{}).Where("accessed_by = ?", "owner").Count(&n).Error)
	assert.Equal(t, int64(1), n, "the same reference occurring 3 times in one template must log exactly one read")
}

// Distinct references, by contrast, each produce their own access-log row.
func TestRenderSecretTemplate_DistinctReferencesEachLogged(t *testing.T) {
	ctx := context.Background()
	c, db, projectID := newRenderFixture(t)

	st := store.NewLocalStorage(db)
	secret2, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "api-key", ProjectID: projectID, EnvironmentID: firstEnvID(t, db, projectID), Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret2.ID, VersionNumber: 1, EncryptedValue: []byte("k3y"),
	})
	require.NoError(t, err)

	_, err = c.RenderSecretTemplate(ctx,
		"A=${secret:production/db-password} B=${secret:production/api-key}",
		projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err)

	var n int64
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		require.NoError(t, db.Model(&models.SecretAccessLog{}).Where("accessed_by = ?", "owner").Count(&n).Error)
		if n >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.Equal(t, int64(2), n, "two distinct references must each produce their own access-log row")
}

func firstEnvID(t *testing.T, db *gorm.DB, projectID uint) uint {
	t.Helper()
	var env models.Environment
	require.NoError(t, db.Where("project_id = ?", projectID).First(&env).Error)
	return env.ID
}
