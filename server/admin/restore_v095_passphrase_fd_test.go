package admin

import (
	"fmt"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// TestAdminRestore_V0953Archive_PassphraseFDFlag pins REVIEW-3807's
// passphrase-resolve-once fix through the flag an operator actually types.
// v0953PassphraseInputs assigns restorePassphraseSource directly; this one
// parses `--passphrase-fd <n>` on the restore command, so a regression in the
// flag wiring (the fd silently ignored) or in resolving the one-shot source a
// second time after the commit (EOF on the drained pipe, plaintext webhook URL
// left behind) fails here against the real v0.95.3 archive.
func TestAdminRestore_V0953Archive_PassphraseFDFlag(t *testing.T) {
	restoreWithFDFlag := func(t *testing.T, storageBlock func(dir string) string) {
		setupV0953ArchiveRestore(t, storageBlock)
		t.Setenv("KEYORIX_MASTER_PASSWORD", "") // only the fd may supply it

		r := v0953PassphrasePipe(t)
		fd, err := syscall.Dup(int(r.Fd())) // the reader closes the fd it is given
		require.NoError(t, err)
		require.NoError(t, r.Close())

		old := restorePassphraseSource
		t.Cleanup(func() { restorePassphraseSource = old })
		restorePassphraseSource = crypto.PassphraseSource{}
		require.NoError(t, restoreCmd.ParseFlags([]string{"--passphrase-fd", strconv.Itoa(fd)}))
		require.True(t, restorePassphraseSource.FDSet, "--passphrase-fd must be honoured by the flag")
		require.Equal(t, fd, restorePassphraseSource.FD)

		out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
		require.NoError(t, err, "restore output:\n%s", out)
		require.Contains(t, out, "verify-audit on the restored database: VALID")
		requireV0953ArchiveRestored(t, out)
	}

	t.Run("SQLite", func(t *testing.T) {
		restoreWithFDFlag(t, func(dir string) string {
			return fmt.Sprintf("  type: local\n  database:\n    path: %s\n", filepath.Join(dir, "secrets.db"))
		})
	})
	t.Run("Postgres", func(t *testing.T) {
		base := pgAdminTestDSN(t)
		restoreWithFDFlag(t, func(string) string {
			return fmt.Sprintf("  type: postgres\n  database:\n    dsn: %q\n", pgAdminIsolatedDatabaseDSN(t, base))
		})
	})
}
