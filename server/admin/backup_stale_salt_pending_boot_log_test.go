package admin

// #4105 (option 2): the WARN a successful boot logs for a salt-only staging
// file says what the file costs (backups refused until it is moved), not only
// that it "can be deleted". Boot still keeps the file.

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBootLeavesStaleSaltPending_WarnsThatBackupsRefuseUntilMoved(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	plantStagingFiles(t, testSaltPending)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	recoverLikeBoot(t)

	require.FileExists(t, testSaltPending, "boot keeps the file: only the log line changed")
	var lines []string
	for _, l := range bytes.SplitSeq(buf.Bytes(), []byte("\n")) {
		if bytes.Contains(l, []byte(testSaltPending)) {
			lines = append(lines, string(l))
		}
	}
	require.Len(t, lines, 1, "exactly one WARN line names the staging salt; log:\n%s", buf.String())
	require.Contains(t, lines[0], "[WARN] key set:")
	require.Contains(t, lines[0], "admin backup` will refuse until "+testSaltPending+" is moved away")
	require.Contains(t, lines[0], "can be deleted", "the existing wording stays")
}
