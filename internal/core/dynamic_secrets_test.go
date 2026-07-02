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

func TestDynamicSecrets_MaxActiveLeasesCeiling(t *testing.T) {
	c, _, _, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "capped", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: adminDSNPlain, CreationTemplate: "GRANT SELECT TO {{name}};",
		DefaultTTLSeconds: 3600, MaxActiveLeases: 2, CreatedBy: "alice",
	})
	require.NoError(t, err)

	// Two leases are allowed...
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	// ...the third exceeds the ceiling.
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active-lease limit")

	// Revoking one frees a slot.
	leases, err := c.ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, err)
	require.NoError(t, c.RevokeLease(ctx, leases[0].LeaseID, 7, "manual"))
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err, "a slot opens after a revoke")
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

// A revoke_failed lease (its credential still live) must remain retryable — manually and
// via the sweep — not be a terminal dead-end. The sweep also surfaces a persistent
// failure as an error so a mass TTL-enforcement outage isn't reported as a clean pass.
func TestDynamicSecrets_RevokeFailedIsRetryable(t *testing.T) {
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// First revoke fails on the target → revoke_failed (the credential is still live).
	fake.FailRevoke = true
	require.Error(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"))
	failed, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.Equal(t, "revoke_failed", failed.Status)

	// A manual retry must be ACCEPTED (not rejected as "not active"). While the target is
	// still down it fails again — but the lease stays retryable.
	require.Error(t, c.RevokeLease(ctx, issued.LeaseID, 7, "retry"), "retry is attempted, not refused")

	// Backdate past expiry: the sweep must pick up the revoke_failed lease and, while the
	// target is still down, surface the persistent failure as a non-nil error.
	failed.ExpiresAt = fixed.Add(-time.Hour)
	require.NoError(t, c.storage.UpdateDynamicSecretLease(ctx, failed))
	_, serr := c.RevokeExpiredLeases(ctx, fixed)
	require.Error(t, serr, "the sweep surfaces a still-failing revoke")

	// The target recovers — the sweep now drops the credential and the lease is revoked.
	fake.FailRevoke = false
	n, err := c.RevokeExpiredLeases(ctx, fixed)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	done, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoked", done.Status)
	assert.Contains(t, fake.Revoked, issued.Username)
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

// An ephemeral (cloud-IAM, e.g. AWS STS) backend surfaces its credential via Fields
// and refuses renewal — its lifetime is fixed by the provider at issue.
func TestDynamicSecrets_EphemeralBackendFieldsAndRenewRefused(t *testing.T) {
	c, _, fake, _ := newDynamicTestCore(t)
	fake.Ephemeral = true
	fake.IssueFields = map[string]string{"access_key_id": "AKIA", "session_token": "tok"}
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	assert.Equal(t, "AKIA", issued.Fields["access_key_id"])
	assert.Equal(t, "tok", issued.Fields["session_token"])

	_, err = c.RenewLease(ctx, issued.LeaseID, 1200, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be renewed")
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

// #192: the bulk incident-response kill switch is the LAST line of defense for
// MySQL/Mongo/Redis, where the target DROP/dropUser/ACL-DELUSER call is the only
// enforcement mechanism. A lease already stuck in revoke_failed (its credential still
// live from an earlier failed attempt) must NOT be silently skipped by
// RevokeLeasesForConfig — it must be retried right alongside the still-active leases,
// so an operator responding to "this target/config is compromised" actually kills every
// outstanding credential, not just the ones that happened to revoke cleanly before.
func TestDynamicSecrets_RevokeLeasesForConfigRetriesRevokeFailed(t *testing.T) {
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	stuck, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	stillActive, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// The first lease's revoke fails once (transient outage) and is left revoke_failed —
	// its credential is still live on the target.
	fake.FailRevoke = true
	require.Error(t, c.RevokeLease(ctx, stuck.LeaseID, 7, "manual"))
	before, _ := c.storage.GetDynamicSecretLease(ctx, stuck.LeaseID)
	require.Equal(t, "revoke_failed", before.Status, "precondition: the lease is stuck exactly as #192 describes")

	// The target recovers, and an incident responder now believes the whole config is
	// compromised and pulls the kill switch.
	fake.FailRevoke = false
	revoked, failed, err := c.RevokeLeasesForConfig(ctx, cfg.ID, 7, "incident: compromised target")
	require.NoError(t, err)
	assert.Equal(t, 0, failed)
	assert.Equal(t, 2, revoked, "both the still-active lease AND the previously revoke_failed one must be revoked")

	after, _ := c.storage.GetDynamicSecretLease(ctx, stuck.LeaseID)
	assert.Equal(t, "revoked", after.Status, "the revoke_failed lease is NOT permanently stuck — the kill switch reaches it")
	assert.Empty(t, after.RevokeError, "a successful retry clears the earlier error")
	assert.Contains(t, fake.Revoked, stuck.Username, "the previously-stranded credential was actually dropped on the target")
	assert.Contains(t, fake.Revoked, stillActive.Username)
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

// A lease whose expiry has already passed must not be renewable even while its status
// is still "active" (the sweeper has not flipped it yet, or is disabled). Renewing it
// would push the backend credential's lifetime forward and resurrect a credential that
// should be dead, so RenewLease must refuse and must NOT call the engine.
func TestDynamicSecrets_RenewRejectsExpiredLease(t *testing.T) {
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	// Backdate the lease past its expiry while leaving status "active" (pre-sweep).
	lease, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	lease.ExpiresAt = fixed.Add(-time.Minute)
	require.NoError(t, c.storage.UpdateDynamicSecretLease(ctx, lease))
	require.Equal(t, "active", lease.Status)

	_, err = c.RenewLease(ctx, issued.LeaseID, 1200, 7)
	require.Error(t, err, "an expired lease cannot be renewed")
	assert.Contains(t, err.Error(), "expired")
	assert.NotContains(t, fake.Renewed, issued.Username, "the engine must not renew a dead credential")
}

// TestDynamicSecrets_RealFactoryValidatesBackend checks the real engine factory
// (no fake): config creation accepts the supported backends and rejects others.
func TestDynamicSecrets_RealFactoryValidatesBackend(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}, &models.AuditEvent{}))
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}

	for _, backend := range []string{"postgres", "mysql", "mongodb", "redis"} {
		_, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
			Name: backend + "-cfg", ProjectID: 1, BackendType: backend, AdminDSN: "admin:p@tcp(h:3306)/",
		})
		require.NoError(t, err, "backend %s must be accepted", backend)
	}

	_, err = c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "bad", ProjectID: 1, BackendType: "cassandra", AdminDSN: "x",
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
