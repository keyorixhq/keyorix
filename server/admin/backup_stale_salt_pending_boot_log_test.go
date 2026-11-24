package admin

// #4105 (option 2): the WARN a successful boot logs for a salt-only staging
// file says what the file costs (backups refused until it is moved), not only
// that it "can be deleted". Boot still keeps the file.

import (
	"log"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBootLeavesStaleSaltPending_WarnsThatBackupsRefuseUntilMoved(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	plantStagingFiles(t, testSaltPending)

	// A mutex-guarded capture (#4501): goroutines that other tests in this
	// package leave running (storage's trigger-integrity check) log through the
	// standard logger at any time, so the buffer is only read through copies
	// taken under its lock. The noise goroutine below is that leak made
	// deterministic: with a bare bytes.Buffer this test fails under -race.
	logs := captureLog(t)
	stop := make(chan struct{})
	var noise sync.WaitGroup
	noise.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				log.Printf("background logger of another test: tick")
				time.Sleep(50 * time.Microsecond)
			}
		}
	})
	defer func() {
		close(stop)
		noise.Wait()
	}()

	recoverLikeBoot(t)

	require.FileExists(t, testSaltPending, "boot keeps the file: only the log line changed")
	// recoverLikeBoot is synchronous: the WARN is in the capture when it returns.
	lines := logs.Lines(testSaltPending)
	require.Len(t, lines, 1, "exactly one WARN line names the staging salt; log:\n%s", logs.String())
	require.Contains(t, lines[0], "[WARN] key set:")
	require.Contains(t, lines[0], "admin backup` will refuse until "+testSaltPending+" is gone: with the server stopped, run `keyorix-server admin encryption clear-stale-salt-pending`")
	require.Contains(t, lines[0], "can be deleted", "the existing wording stays")
}
