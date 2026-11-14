// upgrade_v096_audit_verify_test.go -- #3743 (DEMO-GATE-UPGRADE-1): what
// `audit verify` says right after a v0.96.x install is upgraded in place.
//
// testdata/upgrade-fixtures/v096-audit is a REAL v0.96.3 SQLite database and
// its key files, written by the v0.96.3 tag's own server and CLI binaries:
// `admin init --dev`, `admin encryption init`, `admin migrate`, server start
// (which wrote signed checkpoint #1 at head 39), `system init`, `login`, one
// secret created and updated once (value "v2-value"), `audit verify` VALID at
// head 44, then a graceful stop. The database was compacted with
// `VACUUM INTO`; nothing else was changed. v0.96.x wrote checkpoints but no
// incremental-verification state row (audit_verification_state), which is
// the shape this test is about.
package core

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openV096AuditFixture opens a copy of the fixture through HEAD's real
// migration path and wires a core the way server start does
// (wireSecretEncryption + the audit-checkpoint scheduler setup), with now set
// to one hour after the v0.96.3 checkpoint: the operator swapped the binaries
// right after stopping the old server.
func openV096AuditFixture(t *testing.T) (*KeyorixCore, *gorm.DB, upgradeFuzzManifest) {
	t.Helper()
	srcDir := filepath.Join("testdata", "upgrade-fixtures", "v096-audit")
	manifest := loadUpgradeFuzzManifest(t, filepath.Join(srcDir, "manifest.json"))
	workDir := t.TempDir()
	dbPath := filepath.Join(workDir, "fixture.db")
	copyFileT(t, filepath.Join(srcDir, "fixture.db"), dbPath)
	copyFileT(t, filepath.Join(srcDir, "dek.key"), filepath.Join(workDir, "dek.key"))
	copyFileT(t, filepath.Join(srcDir, "kek.salt"), filepath.Join(workDir, "kek.salt"))

	cfg := &config.Config{Storage: config.StorageConfig{
		Type:       "local",
		Database:   config.DatabaseConfig{Path: dbPath},
		Encryption: config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"},
	}}
	st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "HEAD's migration path on a %s database", manifest.SourceTag)
	enc := encryption.NewService(&cfg.Storage.Encryption, workDir)
	require.NoError(t, enc.Initialize(manifest.Passphrase))

	c := NewKeyorixCore(st)
	c.SetSecretValueEncryptor(enc)
	c.SetAuthEncryptor(enc)
	key, keyVer, ok := enc.AuditCheckpointKey()
	require.True(t, ok, "encryption on: the checkpoint key is available")
	c.SetAuditCheckpointKey(key, keyVer)
	c.SeedAuditWatermark(context.Background())

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	if sqlDB, e := db.DB(); e == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	var cp models.AuditCheckpoint
	require.NoError(t, db.Order("id DESC").First(&cp).Error)
	now := cp.CreatedAt.Add(time.Hour)
	c.now = func() time.Time { return now }
	c.SetAuditIncrementalVerification(24*time.Hour, DefaultAuditFullVerificationSegments)
	return c, db, manifest
}

// The upgrade is clean: data decrypts and the whole chain verifies. Plain
// verify says not_proven with a reason that names the missing full
// verification, never broken and never valid. The first scheduler tick is not
// deferred behind the fresh v0.96.3 checkpoint (it was, by up to 24 h: #3743),
// and that one tick makes plain verify valid. Afterwards the normal deferral
// applies again.
func TestUpgradeFromV096_AuditVerifyProvenAtFirstTick(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, manifest := openV096AuditFixture(t)
	day := 24 * time.Hour

	for idStr, want := range manifest.SecretValues {
		id, err := strconv.ParseUint(idStr, 10, 64)
		require.NoError(t, err)
		got, err := c.GetSecretValue(ctx, uint(id))
		require.NoError(t, err)
		assert.Equal(t, want, string(got), "secret %d after the upgrade", id)
	}

	full, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, full.Valid, "the v0.96.3 chain is intact after the upgrade: %s", full.Reason)

	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status, "nothing proved the rows before the v0.96.3 checkpoint head yet")
	assert.Contains(t, r.NotProvenReason, "no full verification has completed yet")
	assert.Nil(t, r.FirstBrokenID)
	assert.Empty(t, r.Reason, "not_proven, not broken")
	require.NotNil(t, r.Coverage)
	assert.True(t, r.Coverage.TailComplete)
	assert.Equal(t, uint(39), r.Coverage.TailFromID, "the tail check stands on the v0.96.3 checkpoint")

	assert.Zero(t, c.AuditCheckpointFirstTickDelay(ctx, day),
		"no verification state yet: the first tick must not wait behind the fresh v0.96.3 checkpoint")

	res, err := c.RunAuditVerificationTick(ctx)
	require.NoError(t, err)
	require.True(t, res.Written)
	require.True(t, res.CycleCompleted, "a small chain completes a whole cycle in one tick")
	r = incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusValid, r.Status, "after the first tick: %s", r.NotProvenReason)
	require.NotNil(t, r.LastFullVerificationAt)

	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Where("id = ?", res.Checkpoint.ID).
		Update("created_at", c.now().Add(-time.Hour)).Error)
	assert.Equal(t, 23*time.Hour, c.AuditCheckpointFirstTickDelay(ctx, day),
		"with a full verification recorded, a restart defers the tick as before")
}

// The early first tick never turns a damaged v0.96.3 chain into a pass: a row
// below the v0.96.3 checkpoint head edited before the upgrade (no hash
// rewritten) reads not_proven before the tick, as above, and broken after it,
// naming the row.
func TestUpgradeFromV096_TamperedChainBrokenAtFirstTick(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, _ := openV096AuditFixture(t)
	tamperDescription(t, db, 10)

	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusNotProven, r.Status, "row 10 is below the checkpoint head: only a full walk can see it")

	_, _ = c.RunAuditVerificationTick(ctx)
	r = incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status)
	require.NotNil(t, r.FirstBrokenID)
	assert.Equal(t, uint(10), *r.FirstBrokenID)
}
