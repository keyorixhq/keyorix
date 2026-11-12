package admin

// #4104's single-directory side (SQLite, one key directory, no DEK epoch): the
// interrupted DEK rotation leaves dek.key.pending in the one directory, and the
// existing local refusal (#4058) is what fires, unchanged by the database check.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func insertSQLiteRedoMarker(t *testing.T) {
	t.Helper()
	cfg, err := loadConfig()
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	defer closeGormDB(gdb)
	require.NoError(t, gdb.Create(&models.SystemMetadata{Key: encryption.DEKRotationPromotePendingMetadataKey, Value: "v2"}).Error)
}

func TestAdminBackup_SQLite_InterruptedDEKRotationKeepsThePendingFileRefusal(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	insertSQLiteRedoMarker(t)
	stderr := requireRefusedAndUntouched(t, plantStagingFiles(t, testDEKPending))
	require.NotContains(t, stderr, "a DEK rotation committed its re-encryption sweep",
		"SQLite has one key directory: the local .pending refusal explains the state")
}

// A redo marker without a pending file on SQLite is a completed rotation's (its
// rename happened): the backup is not refused, as before.
func TestAdminBackup_SQLite_CompletedRotationMarkerDoesNotRefuse(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	insertSQLiteRedoMarker(t)
	code, stderr := runBackupCommand(t, t.TempDir()+"/backup.tar.gz")
	require.Zero(t, code, "stderr:\n%s", stderr)
}

// The PostgreSQL test plants the marker by its literal key so it also runs on a
// tree without the fix; this keeps that literal in step with the constant.
func TestDEKRotationMarkerKeyLiteral(t *testing.T) {
	require.Equal(t, "dek_rotation.promote_pending", encryption.DEKRotationPromotePendingMetadataKey)
	require.Equal(t, "dek.epoch", encryption.DEKEpochMetadataKey)
	require.Equal(t, "rotating:", encryption.DEKEpochRotatingPrefix)
}
