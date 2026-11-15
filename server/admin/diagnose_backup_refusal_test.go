package admin

// #4105 (option 2): `admin diagnose` says that backups would be refused while a
// key-rotation staging file is present, with the refusal's own steps.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func diagnoseBackupRefusalOutput(t *testing.T) string {
	t.Helper()
	cfg, err := loadConfig()
	require.NoError(t, err)
	out, err := captureStdout(t, func() error { diagnoseBackupRefusal(cfg); return nil })
	require.NoError(t, err)
	return out
}

const diagnoseBackupRefusalLine = "[WARN] backups would be refused: staging file present"

func TestDiagnose_ReportsStagingSaltBackupRefusal(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	require.NotContains(t, diagnoseBackupRefusalOutput(t), "backups would be refused", "control: no staging file")

	plantStagingFiles(t, testSaltPending)
	out := diagnoseBackupRefusalOutput(t)
	require.Contains(t, out, diagnoseBackupRefusalLine+" ("+testSaltPending+")", "output:\n%s", out)
	require.Contains(t, out, "move it out of the key directory (mv "+testSaltPending)
	require.Contains(t, out, "no `admin encryption rotate-kek` is running")
	require.NotContains(t, out, "never delete by hand")
	require.FileExists(t, testSaltPending, "diagnose is read-only")
}

func TestDiagnose_ReportsStagingDEKBackupRefusal_NeverDeleteByHand(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	plantStagingFiles(t, testDEKPending)

	out := diagnoseBackupRefusalOutput(t)
	require.Contains(t, out, diagnoseBackupRefusalLine+" ("+testDEKPending+")", "output:\n%s", out)
	require.Contains(t, out, "never delete by hand; recover with rotate-kek recovery")
	require.NotContains(t, out, "move it out of the key directory")
	require.FileExists(t, testDEKPending, "diagnose is read-only")
}
