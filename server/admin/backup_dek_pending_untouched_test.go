package admin

// #4105: a DEK's staging file can be the only copy of the new DEK, so nothing
// that reports or refuses on a staging file may touch it. The backup refusal
// (twice), `admin validate --posture`, `admin diagnose` and boot's key-set
// reconcile (keyfiles.ReconcileKeySet, the step that keeps an unused staging
// salt) all leave it byte-identical. Boot's next step,
// RecoverInterruptedRotation, settles it by the DEK-rotation redo marker
// (ADR-010: promote or discard) and is not exercised here.

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
)

func requireFilesUnchanged(t *testing.T, want map[string][]byte, step string) {
	t.Helper()
	for name, data := range want {
		got, err := os.ReadFile(name)
		require.NoError(t, err, "%s: %s must survive", step, name)
		require.Equal(t, data, got, "%s: %s must be byte-identical", step, name)
	}
}

func TestDEKPending_SurvivesBackupPostureDiagnoseAndKeySetReconcile(t *testing.T) {
	cases := []struct {
		name  string
		files []string
	}{
		{"DEK staging file only", []string{testDEKPending}},
		{"DEK and salt staging files", []string{testDEKPending, testSaltPending}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetBackupRestoreFlags(t)
			sqliteBackupSource(t)
			planted := plantStagingFiles(t, c.files...)

			for range 2 {
				stderr := requireRefusedAndUntouched(t, planted)
				require.NotContains(t, stderr, "move it out of the key directory (mv "+testDEKPending)
			}
			requireFilesUnchanged(t, planted, "backup")

			require.Contains(t, postureOutput(t), backupRefusedPostureLine)
			requireFilesUnchanged(t, planted, "posture")
			diagnoseBackupRefusalOutput(t)
			requireFilesUnchanged(t, planted, "diagnose")

			cfg, err := loadConfig()
			require.NoError(t, err)
			svc := encryption.NewService(&cfg.Storage.Encryption, ".")
			require.NoError(t, svc.AcquireExclusiveKeyLock())
			require.NoError(t, svc.ReconcileKeySet())
			svc.Shutdown()
			requireFilesUnchanged(t, map[string][]byte{testDEKPending: planted[testDEKPending]}, "key-set reconcile")
		})
	}
}

// The structured line's reason is the token the server reports in
// security.backup_refused, so one match covers both.
func TestBackupRefusedLine_ReasonIsTheServerSignalsReason(t *testing.T) {
	require.True(t, strings.HasPrefix(backupRefusedLine, "keyorix-backup-refused reason="+keyfiles.BackupRefusedReasonStagingFile+" "))
	require.Equal(t, "key-rotation-staging-file", keyfiles.BackupRefusedReasonStagingFile, "a documented, matched-on token: change it only with the docs")
}
