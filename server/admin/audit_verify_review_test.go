package admin

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// REVIEW-AUDITVERIFY-KEYFILES-1: a DB-write actor can delete every checkpoint
// row and the high-water mark; the human report must not then tell the
// operator that no checkpoint was ever written.
func TestVerifyAudit_ErasedCheckpointsNotReportedAsNeverWritten(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)
	db, err := gorm.Open(sqlitedialect.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`DELETE FROM audit_checkpoints`).Error)
	require.NoError(t, db.Exec(`DELETE FROM system_metadata WHERE key = 'audit_checkpoint_highwater'`).Error)
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	configPathFlag = filepath.Join(dir, "never-written.yaml")
	verifyAuditDBPath = dbPath
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)
	out, runErr := captureStdout(t, func() error { return runVerifyAudit(nil, nil) })
	require.NoError(t, runErr, out)
	assert.NotContains(t, out, "has ever been written")
	assert.Contains(t, out, "never written, or deleted")
	assert.Contains(t, out, "no signed checkpoint was found")
}
