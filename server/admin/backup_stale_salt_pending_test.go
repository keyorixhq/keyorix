package admin

// #4105 (option 2): a kek.salt.pending that a successful boot has proved unused
// (keyfiles.ReconcileKeySet leaves it with a warning) refuses every later
// backup. The refusal stays, but it explains itself and `admin validate
// --posture` reports it until the file is gone. Boot behaviour is unchanged.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const backupRefusedPostureLine = "backups are refused: key-rotation staging file present"

func postureOutput(t *testing.T) string {
	t.Helper()
	cfg, err := loadConfig()
	require.NoError(t, err)
	out, _ := captureStdout(t, func() error { return runAdminValidatePosture(cfg, configPathFlag) })
	return out
}

func TestAdminBackup_StaleSaltPendingAfterBoot_RefusedVisiblyUntilRemoved(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	planted := plantStagingFiles(t, testSaltPending)
	recoverLikeBoot(t)
	require.FileExists(t, testSaltPending, "boot leaves an unused staging salt in place (unchanged)")

	for range 2 {
		stderr := requireRefusedAndUntouched(t, planted)
		require.Contains(t, stderr, "has proved that the active key set opens without it")
		require.Contains(t, stderr, "move it out of the key directory (mv "+testSaltPending)
		require.Contains(t, stderr, "no `admin encryption rotate-kek` is running")
		require.Contains(t, stderr, "admin validate --posture")
	}

	out := postureOutput(t)
	require.Contains(t, out, "[backup/explicit] "+backupRefusedPostureLine+" ("+testSaltPending+")", "posture output:\n%s", out)

	require.NoError(t, os.Remove(testSaltPending))
	require.NotContains(t, postureOutput(t), backupRefusedPostureLine)
	code, stderr := runBackupCommand(t, filepath.Join(t.TempDir(), "after.tar.gz"))
	require.Zero(t, code, "stderr:\n%s", stderr)
}

// The DEK's staging file is reported the same way, and its refusal never
// suggests removing it.
func TestPosture_ReportsPendingDEKBackupRefusal(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	require.NotContains(t, postureOutput(t), backupRefusedPostureLine, "control: no staging file")
	plantStagingFiles(t, testDEKPending)
	out := postureOutput(t)
	require.Contains(t, out, backupRefusedPostureLine+" ("+testDEKPending+")", "posture output:\n%s", out)
	require.NotContains(t, out, "move it out of the key directory")
}
