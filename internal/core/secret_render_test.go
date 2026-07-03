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

// #324: rendering a template referencing N distinct secrets must produce N audit_events
// rows and N secret_access_logs rows — one per resolved secret, each attributed to the
// correct secret ID — not one aggregate event for the whole render call. Without this,
// a single POST could bulk-decrypt an arbitrary number of secrets while leaving the
// anomaly detector (which keys off per-secret SecretAccessLog rows) completely blind,
// exactly matching the fetch-N-individually-vs-render-once asymmetry #324 called out.
func TestRenderSecretTemplate_RecordsReadPerSecret(t *testing.T) {
	ctx := context.Background()
	c, db, projectID := newRenderFixture(t)

	// Add two more secrets to the same project/environment alongside db-password.
	env, err := c.storage.ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, env, 1)

	apiKey, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "api-key", ProjectID: projectID, EnvironmentID: env[0].ID, Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: apiKey.ID, VersionNumber: 1, EncryptedValue: []byte("a-p-i"),
	})
	require.NoError(t, err)

	stripeKey, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "stripe-secret", ProjectID: projectID, EnvironmentID: env[0].ID, Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: stripeKey.ID, VersionNumber: 1, EncryptedValue: []byte("sk_live_xyz"),
	})
	require.NoError(t, err)

	dbSecret, err := c.storage.GetSecretByName(ctx, "db-password", projectID, env[0].ID)
	require.NoError(t, err)

	tmpl := "${secret:production/db-password}${secret:production/api-key}${secret:production/stripe-secret}"
	out, err := c.RenderSecretTemplate(ctx, tmpl, projectID, 1, "owner", "10.0.0.1", "ua")
	require.NoError(t, err)
	assert.Equal(t, "s3cr3ta-p-isk_live_xyz", out)

	wantSecretIDs := []uint{dbSecret.ID, apiKey.ID, stripeKey.ID}

	// Reads are logged in detached goroutines — poll briefly for all three rows.
	var gotAccessLogIDs []uint
	var gotAuditSecretIDs []*uint
	for i := 0; i < 200; i++ {
		var logs []models.SecretAccessLog
		require.NoError(t, db.Where("accessed_by = ? AND action = ?", "owner", "read").Find(&logs).Error)
		gotAccessLogIDs = nil
		for _, l := range logs {
			gotAccessLogIDs = append(gotAccessLogIDs, l.SecretNodeID)
		}

		var events []models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", "secret.read").Find(&events).Error)
		gotAuditSecretIDs = nil
		for _, e := range events {
			gotAuditSecretIDs = append(gotAuditSecretIDs, e.SecretNodeID)
		}

		if len(gotAccessLogIDs) >= 3 && len(gotAuditSecretIDs) >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	assert.ElementsMatch(t, wantSecretIDs, gotAccessLogIDs,
		"one secret_access_logs row per resolved secret, correctly attributed")
	require.Len(t, gotAuditSecretIDs, 3, "one audit_events row per resolved secret, not one aggregate event")
	var gotAuditIDs []uint
	for _, id := range gotAuditSecretIDs {
		require.NotNil(t, id, "each secret.read audit event must carry the specific secret's ID")
		gotAuditIDs = append(gotAuditIDs, *id)
	}
	assert.ElementsMatch(t, wantSecretIDs, gotAuditIDs)

	// Every audit event must also carry the project ID for scoping.
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "secret.read").Find(&events).Error)
	for _, e := range events {
		require.NotNil(t, e.ProjectID)
		assert.Equal(t, projectID, *e.ProjectID)
	}
}
