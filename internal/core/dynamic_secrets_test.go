package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const adminDSNPlain = "postgres://admin:s3cr3t@db.internal:5432/app"

// newDynamicTestCore builds a core over real SQLite with an enabled encryptor (so
// at-rest encryption of the admin DSN + issued credential is exercised), a fixed
// clock, and a fake credential engine in place of a real Postgres target.
func newDynamicTestCore(t *testing.T) (*KeyorixCore, *gorm.DB, *dynamic.FakeEngine, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{}))

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	fake := &dynamic.FakeEngine{}
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetAuthEncryptor(enc)
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	return c, db, fake, fixed
}

func mkConfig(t *testing.T, c *KeyorixCore, ctx context.Context) *models.DynamicSecretConfig {
	t.Helper()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name:              "app-db",
		ProjectID:         1,
		EnvironmentID:     2,
		BackendType:       "postgres",
		AdminDSN:          adminDSNPlain,
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600,
		CreatedBy:         "alice",
	})
	require.NoError(t, err)
	return cfg
}

func TestDynamicSecrets_ConfigEncryptsAdminDSN(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	stored, err := c.storage.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.NotContains(t, string(stored.AdminDSNEnc), "s3cr3t", "admin DSN must be encrypted at rest")
	assert.NotEqual(t, adminDSNPlain, string(stored.AdminDSNEnc))
}

func TestDynamicSecrets_IssueListRevoke(t *testing.T) {
	c, db, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	// ── Issue ──
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	require.NotEmpty(t, issued.LeaseID)
	require.NotEmpty(t, issued.Username)
	require.NotEmpty(t, issued.Password)
	assert.Len(t, fake.Issued, 1, "engine issued one role")

	// The credential is encrypted at rest — the stored bytes don't contain the password.
	stored, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	assert.Equal(t, "active", stored.Status)
	assert.NotContains(t, string(stored.CredentialEnc), issued.Password, "credential must be encrypted at rest")

	// ── List ──
	leases, err := c.ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, err)
	require.Len(t, leases, 1)

	// ── Revoke ──
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))
	assert.Equal(t, []string{issued.Username}, fake.Revoked, "engine revoked the issued role")
	after, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoked", after.Status)
	assert.NotNil(t, after.RevokedAt)

	// Revoking an already-revoked lease is rejected.
	require.Error(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))

	_ = db
}

func TestDynamicSecrets_SweepRevokesExpired(t *testing.T) {
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// Backdate the lease past its expiry, then sweep.
	lease, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	lease.ExpiresAt = fixed.Add(-time.Hour)
	require.NoError(t, c.storage.UpdateDynamicSecretLease(ctx, lease))

	n, err := c.RevokeExpiredLeases(ctx, fixed)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Contains(t, fake.Revoked, issued.Username)

	after, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoked", after.Status)
	assert.Equal(t, "expired", after.RevokeReason)
}

func TestDynamicSecrets_RevokeFailureMarksLease(t *testing.T) {
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	fake.FailRevoke = true
	err = c.RevokeLease(ctx, issued.LeaseID, 7, "manual")
	require.Error(t, err, "a target revoke failure surfaces to the caller")

	after, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoke_failed", after.Status, "the lease is flagged for an operator")
	assert.NotEmpty(t, after.RevokeError)
	assert.NotNil(t, after.RevokedAt)
}

func TestDynamicSecrets_IssueRejectsUnknownConfig(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	_, err := c.IssueLease(ctx, 999, 0, 7)
	require.Error(t, err)
}

// TestDynamicSecrets_RealFactoryValidatesBackend checks the real engine factory
// (no fake): config creation accepts the supported backends and rejects others.
func TestDynamicSecrets_RealFactoryValidatesBackend(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}, &models.AuditEvent{}))
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}

	for _, backend := range []string{"postgres", "mysql"} {
		_, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
			Name: backend + "-cfg", ProjectID: 1, BackendType: backend, AdminDSN: "admin:p@tcp(h:3306)/",
		})
		require.NoError(t, err, "backend %s must be accepted", backend)
	}

	_, err = c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "bad", ProjectID: 1, BackendType: "redis", AdminDSN: "x",
	})
	require.Error(t, err, "an unsupported backend must be rejected at config creation")
}
