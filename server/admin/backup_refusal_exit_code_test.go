package admin

// #4105 (option 2): a backup refused on a rotation staging file must be
// machine-visible to the cron job that runs it, not only to a human reading
// stderr. It exits with its own documented code (4), not the generic 1, and
// prints one structured line a wrapper can match. Other failures keep exit 1.

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// The documented contract (docs/SELF_HOSTING.md "When admin backup is
// refused"): literal values on purpose, so a change to either is a visible
// contract change here, not a silent rename.
const (
	wantBackupRefusedExitCode = 4
	backupRefusedLinePrefix   = "keyorix-backup-refused reason=key-rotation-staging-file"
)

func TestAdminBackup_StagingFileRefusal_DistinctExitCodeAndStructuredLine(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files func() []string
	}{
		{"stale salt pending", func() []string { return []string{testSaltPending} }},
		{"dek pending", func() []string { return []string{testDEKPending} }},
		{"both", func() []string { return []string{testDEKPending, testSaltPending} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetBackupRestoreFlags(t)
			sqliteBackupSource(t)
			files := tc.files()
			planted := plantStagingFiles(t, files...)

			code, stderr := runBackupCommand(t, filepath.Join(t.TempDir(), "backup.tar.gz"))
			require.Equal(t, wantBackupRefusedExitCode, code, "stderr:\n%s", stderr)
			requireRefusedAndUntouched(t, planted)

			lines := regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(backupRefusedLinePrefix)+` .*$`).FindAllString(stderr, -1)
			require.Len(t, lines, 1, "exactly one structured refusal line; stderr:\n%s", stderr)
			for _, f := range files {
				require.Contains(t, lines[0], f, "the structured line names every staging file")
			}
			require.Contains(t, lines[0], "exit_code=4")
		})
	}
}

// Control: a backup that fails for another reason keeps the generic exit code
// and prints no staging-file line, so a cron match on either is specific.
func TestAdminBackup_OtherFailure_KeepsExitCodeOne(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "wrong-passphrase-5678")

	code, stderr := runBackupCommand(t, filepath.Join(t.TempDir(), "backup.tar.gz"))
	require.Equal(t, 1, code, "stderr:\n%s", stderr)
	require.NotContains(t, stderr, "keyorix-backup-refused")
}
