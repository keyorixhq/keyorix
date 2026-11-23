package admin

// #4105 as the operator meets it, written only against names that existed
// before the fix (the command line, the audit event types as strings), so the
// same test runs on the pre-fix tree and fails there on behaviour, not on
// compilation: the refused backup leaves no audit event, and there is no
// command to clear the file.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestIssue4105_RefusalAuditedThenClearedByTheNamedCommand(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	plantStagingFiles(t, "kek.salt.pending")
	recoverLikeBoot(t)
	dek, err := os.ReadFile("dek.key")
	require.NoError(t, err)

	code, stderr := runBackupCommand(t, filepath.Join(t.TempDir(), "refused.tar.gz"))
	require.Equal(t, 4, code, "stderr:\n%s", stderr)

	count := func(eventType string) int64 {
		t.Helper()
		cfg, err := loadConfig()
		require.NoError(t, err)
		db, err := storage.OpenGormDB(cfg)
		require.NoError(t, err)
		defer closeGormDB(db)
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
		return n
	}
	require.EqualValues(t, 1, count("admin.backup_refused"), "the refused backup must be in the audit chain")

	var cmdCode int
	cmdErr := captureStderr(t, func() {
		_, _ = captureStdout(t, func() error {
			cmdCode = Execute([]string{"encryption", "clear-stale-salt-pending", "--config", configPathFlag})
			return nil
		})
	})
	require.Zero(t, cmdCode, "stderr:\n%s", cmdErr)
	require.NoFileExists(t, "kek.salt.pending")
	require.EqualValues(t, 1, count("admin.encryption.clear_stale_salt_pending"))
	got, err := os.ReadFile("dek.key")
	require.NoError(t, err)
	require.True(t, bytes.Equal(dek, got), "dek.key must be unchanged")

	code, stderr = runBackupCommand(t, filepath.Join(t.TempDir(), "after.tar.gz"))
	require.Zero(t, code, "stderr:\n%s", stderr)
}
