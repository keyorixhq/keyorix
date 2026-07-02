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
func newRenderFixture(t *testing.T) (*KeyorixCore, *gorm.DB, uint, uint) {
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
	return c, db, proj.ID, secret.ID
}

func TestRenderSecretTemplate(t *testing.T) {
	ctx := context.Background()
	c, _, projectID, _ := newRenderFixture(t)

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

// #181: a nonexistent secret and an existing-but-forbidden secret must be
// indistinguishable to the caller — both resolve to the ErrSecretRefNotFound sentinel,
// which the HTTP handler maps to the identical generic 404 regardless of which case it
// was, so a viewer can't use the render endpoint as a 404-vs-403 existence oracle to
// enumerate real secret names. (The handler-level response-body equivalence is asserted
// in server/http/handlers/secrets_render_test.go; here we assert the underlying sentinel
// the handler switches on is the same for both branches — using the SAME reference for
// both queries so the resolver's own "resolve %q" wrapping can't introduce a difference.)
func TestRenderSecretTemplate_UniformResponseForNotFoundVsForbidden(t *testing.T) {
	ctx := context.Background()
	c, _, projectID, secretID := newRenderFixture(t)

	// User 2 owns nothing and has no share on "db-password", which DOES exist.
	_, forbiddenErr := c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 2, "viewer", "10.0.0.1", "ua")
	require.Error(t, forbiddenErr)
	require.ErrorIs(t, forbiddenErr, ErrSecretRefNotFound, "forbidden case must surface the same sentinel as not-found")

	// Same reference text, but the owning user deletes it first so it truly doesn't
	// exist — this isolates the sentinel/message from the "resolve %q" reference echo.
	require.NoError(t, c.DeleteSecret(ctx, secretID))
	_, notFoundErr := c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 2, "viewer", "10.0.0.1", "ua")
	require.Error(t, notFoundErr)
	require.ErrorIs(t, notFoundErr, ErrSecretRefNotFound, "not-found case must surface the ErrSecretRefNotFound sentinel")

	assert.Equal(t, notFoundErr.Error(), forbiddenErr.Error(), "response for a forbidden secret must be byte-identical to a nonexistent one once the reference text matches")
}

// A render records a secret read (access log) for each resolved reference, so a bulk
// render can't be a covert exfiltration channel invisible to the audit trail and the
// anomaly detector (which feeds on SecretAccessLog).
func TestRenderSecretTemplate_RecordsReads(t *testing.T) {
	ctx := context.Background()
	c, db, projectID, _ := newRenderFixture(t)

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
