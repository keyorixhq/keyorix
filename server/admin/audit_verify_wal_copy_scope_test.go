package admin

// REVIEW-4553-DEEP-1 M1: only `verify-audit --db` verifies a private copy of
// a WAL-mode database. The config-fallback live database and the database a
// restore just wrote are opened in place, so they need no $TMPDIR (the copy
// is the whole vault). The --db copy's signal cleanup:
// audit_verify_signal_cleanup_test.go.
//
// Not t.Parallel(): these tests set package-level flag vars and TMPDIR.

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// seedWALCheckpointedDB is seedCheckpointedDB switched to WAL mode, as
// storage/factory_local.go leaves every keyorix database, and closed cleanly
// (no -wal or -shm left; the header still says WAL).
func seedWALCheckpointedDB(t *testing.T, dbPath string) {
	t.Helper()
	seedCheckpointedDB(t, dbPath)
	db, err := gorm.Open(sqlitedialect.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	var mode string
	require.NoError(t, db.Raw(`PRAGMA journal_mode=WAL`).Scan(&mode).Error)
	require.Equal(t, "wal", mode)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
}

func missingTMPDIR(t *testing.T) {
	t.Helper()
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
}

func TestVerifyRestoredAudit_WALDatabaseNeedsNoTempDir(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keyorix.db")
	seedWALCheckpointedDB(t, dbPath)
	missingTMPDIR(t)

	_, err := captureStdout(t, func() error { return verifyRestoredAudit(&config.Config{}, dbPath) })
	require.NoError(t, err)
}

func TestVerifyAudit_ConfigFallbackWALDatabaseNeedsNoTempDir(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedWALCheckpointedDB(t, dbPath)
	configPathFlag = writeOfflineAnchorTestConfig(t, dir, dbPath, "")
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)
	missingTMPDIR(t)

	out, err := captureStdout(t, func() error { return runVerifyAudit(nil, nil) })
	require.NoError(t, err, out)
	require.Contains(t, out, "Verdict: VALID")
}

// The --db path still copies, so the missing TMPDIR is reported, and says
// what to do.
func TestVerifyAudit_DBFlagWALDatabaseStillCopies(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedWALCheckpointedDB(t, dbPath)
	configPathFlag = filepath.Join(dir, "never-written.yaml")
	verifyAuditDBPath = dbPath
	missingTMPDIR(t)

	_, err := captureStdout(t, func() error { return runVerifyAudit(nil, nil) })
	require.ErrorContains(t, err, "set TMPDIR to a writable directory")
}
