// AUDIT-VERIFY-ONLINE-1 item 3: verify-audit takes the SHA-256 of the --anchor
// file (as accept-loss does) and compares it with the anchor digest a seal
// recorded with --anchor-sha256, and it prints the rows a seal recorded as
// unpinned. Not t.Parallel(): see audit_offline_anchor_test.go.
package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// openSealTestDB opens dbPath with the server write path; the caller closes it.
func openSealTestDB(t *testing.T, dbPath string) (*gorm.DB, *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlitedialect.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetAuditCheckpointKey(offlineAnchorTestKey, "v1")
	return db, c
}

func closeSealTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
}

func TestVerifyAudit_SealAnchorDigestAndUnpinnedReported(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")

	db, c := openSealTestDB(t, dbPath)
	tr := true
	for range 12 {
		require.NoError(t, store.NewLocalStorage(db).LogAuditEvent(t.Context(), &models.AuditEvent{EventType: "secret.read", Success: &tr, ActorType: "user"}))
	}
	_, written, err := c.WriteAuditCheckpoint(t.Context())
	require.NoError(t, err)
	require.True(t, written)
	closeSealTestDB(t, db)

	// The anchor file kept elsewhere: an export-checkpoint of the chain before the loss.
	anchorPath := filepath.Join(dir, "checkpoint-export.json")
	configPathFlag = writeOfflineAnchorTestConfig(t, dir, dbPath, "")
	exportCheckpointOutput = anchorPath
	require.NoError(t, runExportCheckpoint(nil, nil))
	data, err := os.ReadFile(anchorPath)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	// Row 4 is lost; the loss is accepted with --anchor-sha256 only.
	db, c = openSealTestDB(t, dbPath)
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id = 4").Error)
	plan, err := c.PlanAuditLossAcceptance(t.Context(), core.AuditLossRequest{BrokenIDs: []uint{5}, Operator: "ops", OSUser: "keyorix",
		Reason: "INC-12", Evidence: digest, AnchorDigest: digest})
	require.NoError(t, err)
	_, err = c.AcceptAuditLoss(t.Context(), plan)
	require.NoError(t, err)
	closeSealTestDB(t, db)

	verifyAuditDBPath = dbPath
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
