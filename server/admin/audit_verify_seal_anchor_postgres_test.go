// SEC-PG-TAILS-1 item 1: the real-PostgreSQL counterpart of
// TestVerifyAudit_SealAnchorDigestAndUnpinnedReported (audit_verify_seal_anchor_test.go).
// Same scenario and assertions: a seal accepted with --anchor-sha256 reports the
// anchor digest (not checked / matches / DIFFERS), prints the rows it recorded as
// unpinned, and leaves the exit status (4, SEALED) unchanged. Gated on
// KEYORIX_TEST_PG_DSN (pgAdminTestDSN skips otherwise). Not t.Parallel(): see
// audit_offline_anchor_test.go.
package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// openSealAnchorPG opens dsn with the server write path (store.LocalStorage on
// the Postgres dialect) and migrates the audit tables; the caller closes it
// with closeSealAnchorPG so the admin commands can reconnect without holding
// this handle's connections.
func openSealAnchorPG(t *testing.T, dsn string) (*gorm.DB, *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetAuditCheckpointKey(offlineAnchorTestKey, "v1")
	return db, c
}

func closeSealAnchorPG(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
}

// writeSealAnchorPGConfig is writeOfflineAnchorTestConfig for a Postgres DSN.
func writeSealAnchorPGConfig(t *testing.T, dir, dsn string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	content := fmt.Sprintf("storage:\n  type: postgres\n  database:\n    dsn: %q\n", dsn)
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	return cfgPath
}

func TestVerifyAudit_SealAnchorDigestAndUnpinnedReported_Postgres(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	dir := t.TempDir()

	db, c := openSealAnchorPG(t, dsn)
	tr := true
	for range 12 {
		require.NoError(t, store.NewLocalStorage(db).LogAuditEvent(t.Context(), &models.AuditEvent{EventType: "secret.read", Success: &tr, ActorType: "user"}))
	}
	_, written, err := c.WriteAuditCheckpoint(t.Context())
	require.NoError(t, err)
	require.True(t, written)
	closeSealAnchorPG(t, db)

	// The anchor file kept elsewhere: an export-checkpoint of the chain before the loss.
	anchorPath := filepath.Join(dir, "checkpoint-export.json")
	configPathFlag = writeSealAnchorPGConfig(t, dir, dsn)
	exportCheckpointOutput = anchorPath
	require.NoError(t, runExportCheckpoint(nil, nil))
	data, err := os.ReadFile(anchorPath)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	// Row 4 is lost; the loss is accepted with --anchor-sha256 only.
	db, c = openSealAnchorPG(t, dsn)
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id = 4").Error)
	plan, err := c.PlanAuditLossAcceptance(t.Context(), core.AuditLossRequest{BrokenIDs: []uint{5}, Operator: "ops", OSUser: "keyorix",
		Reason: "INC-12", Evidence: digest, AnchorDigest: digest})
	require.NoError(t, err)
	_, err = c.AcceptAuditLoss(t.Context(), plan)
	require.NoError(t, err)
	closeSealAnchorPG(t, db)

	verifyAuditPGDSN = dsn
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)
	run := func() string {
		out, runErr := captureStdout(t, func() error { return runVerifyAudit(nil, nil) })
		var ec *exitCodeError
		require.ErrorAs(t, runErr, &ec)
		assert.Equal(t, 4, ec.code, "SEALED: %s", out)
		return out
	}

	out := run()
	assert.Contains(t, out, "unpinned: audit events #1 through #3 were pinned by no signed checkpoint")
	assert.Contains(t, out, "anchor sha256 "+digest+" (recorded by digest only): not checked: pass that file with --anchor")

	verifyAuditAnchorFile = anchorPath
	out = run()
	assert.Contains(t, out, "  sha256 "+digest)
	assert.Contains(t, out, "anchor sha256 "+digest+" (recorded by digest only): matches the supplied --anchor, which authenticates and covers the lost range")

	other := filepath.Join(dir, "other.json")
	require.NoError(t, os.WriteFile(other, append(data, '\n'), 0o600))
	verifyAuditAnchorFile = other
	out = run()
	assert.Contains(t, out, "DIFFERS from the supplied --anchor")

	verifyAuditJSON = true
	res, _ := runVerifyAuditCapturingJSON(t)
	require.Len(t, res.Seal.Seals, 1)
	require.NotNil(t, res.Seal.Seals[0].Anchor)
	assert.Equal(t, "differs", res.Seal.Seals[0].Anchor.Check)
	assert.Len(t, res.Seal.Seals[0].Unpinned, 1)
}
