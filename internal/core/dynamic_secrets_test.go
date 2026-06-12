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

	// The default config in these tests is a "postgres" target, so the fake mimics a
	// backend with DB-level expiry (VALID UNTIL) — issuing does not require the
	// sweeper. Tests that exercise the no-native-expiry gate flip NativeExpiry off.
	fake := &dynamic.FakeEngine{NativeExpiry: true}
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

func TestDynamicSecrets_MaxTTLClampsIssue(t *testing.T) {
	c, _, _, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "capped", ProjectID: 1, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 600, MaxTTLSeconds: 1800,
	})
	require.NoError(t, err)

	// Request 1h but the config caps at 30m → expiry is now+30m.
	issued, err := c.IssueLease(ctx, cfg.ID, 3600, 7)
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(30*time.Minute), issued.ExpiresAt, "issue TTL must be clamped to max_ttl_seconds")
}

func TestDynamicSecrets_CreateRejectsDefaultOverMax(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	_, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "bad", ProjectID: 1, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 3600, MaxTTLSeconds: 600,
	})
	require.Error(t, err)
}

func TestDynamicSecrets_RenewExtendsAndRespectsMaxTTL(t *testing.T) {
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "renewable", ProjectID: 1, BackendType: "postgres", AdminDSN: adminDSNPlain,
		DefaultTTLSeconds: 600, MaxTTLSeconds: 1200, // 10m default, 20m hard cap
	})
	require.NoError(t, err)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7) // expiry = fixed+10m
	require.NoError(t, err)
	require.Equal(t, fixed.Add(10*time.Minute), issued.ExpiresAt)

	// Renew for 20m from now; the fixed clock means now=issue time, so the new
	// expiry is fixed+20m — exactly the IssuedAt+max ceiling, extending from +10m.
	exp, err := c.RenewLease(ctx, issued.LeaseID, 1200, 7)
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(20*time.Minute), exp)
	assert.Contains(t, fake.Renewed, issued.Username, "the engine renewed the role")

	// A further renewal can't extend past IssuedAt+max (20m) → rejected.
	_, err = c.RenewLease(ctx, issued.LeaseID, 1200, 7)
	require.Error(t, err, "renewal beyond the max-TTL ceiling is rejected")
}

func TestDynamicSecrets_RevokeLeasesForConfig(t *testing.T) {
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	i1, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	i2, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	revoked, failed, err := c.RevokeLeasesForConfig(ctx, cfg.ID, 7, "incident")
	require.NoError(t, err)
	assert.Equal(t, 2, revoked)
	assert.Equal(t, 0, failed)
	assert.ElementsMatch(t, []string{i1.Username, i2.Username}, fake.Revoked)

	// Both leases are now revoked; a second bulk-revoke finds nothing active.
	for _, lid := range []string{i1.LeaseID, i2.LeaseID} {
		l, _ := c.storage.GetDynamicSecretLease(ctx, lid)
		assert.Equal(t, "revoked", l.Status)
	}
	revoked2, _, err := c.RevokeLeasesForConfig(ctx, cfg.ID, 7, "incident")
	require.NoError(t, err)
	assert.Equal(t, 0, revoked2)
}

func TestDynamicSecrets_RenewRejectsInactiveLease(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))
	_, err = c.RenewLease(ctx, issued.LeaseID, 0, 7)
	require.Error(t, err, "a revoked lease cannot be renewed")
}

// TestDynamicSecrets_RealFactoryValidatesBackend checks the real engine factory
// (no fake): config creation accepts the supported backends and rejects others.
func TestDynamicSecrets_RealFactoryValidatesBackend(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}, &models.AuditEvent{}))
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}

	for _, backend := range []string{"postgres", "mysql", "mongodb"} {
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

// A backend without DB-level expiry (MySQL/MongoDB) must not issue while the
// auto-revoke sweeper is disabled — otherwise the lease TTL is never enforced.
func TestDynamicSecrets_IssueRequiresSweeperForNoExpiryBackend(t *testing.T) {
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	fake.NativeExpiry = false // mimic MySQL/MongoDB

	// Sweeper disabled (the default): refuse, and mint nothing.
	_, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sweep_enabled")
	assert.Empty(t, fake.Issued, "no role is minted when the issue is refused")

	// Enable the sweeper → issuing proceeds.
	c.SetDynamicSweepEnabled(true)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	assert.NotEmpty(t, issued.LeaseID)
	assert.Len(t, fake.Issued, 1)
}

// A failed cleanup-revoke after an aborted issue must leave a visible
// revoke_failed lease (so the orphaned target role is not silently permanent),
// while a clean drop records nothing.
func TestDynamicSecrets_CleanupOrphanedRole(t *testing.T) {
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	t.Run("clean drop leaves no trace", func(t *testing.T) {
		c.cleanupOrphanedRole(ctx, cfg, fake, adminDSNPlain, "kx_orphan_ok", 7)
		assert.Contains(t, fake.Revoked, "kx_orphan_ok")
		leases, err := c.ListDynamicSecretLeases(ctx, cfg.ID)
		require.NoError(t, err)
		assert.Empty(t, leases, "a clean drop records no lease")
	})

	t.Run("failed drop records a revoke_failed lease", func(t *testing.T) {
		fake.FailRevoke = true
		c.cleanupOrphanedRole(ctx, cfg, fake, adminDSNPlain, "kx_orphan_stuck", 7)
		leases, err := c.ListDynamicSecretLeases(ctx, cfg.ID)
		require.NoError(t, err)
		require.Len(t, leases, 1)
		assert.Equal(t, "revoke_failed", leases[0].Status)
		assert.Equal(t, "kx_orphan_stuck", leases[0].RoleName)
		assert.Contains(t, leases[0].RevokeError, "orphaned")
	})
}
