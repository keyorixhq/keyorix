//go:build darwin

package securefiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// SecureCreateFile and SecureCreateFileSync must report a failed Write. With
// RLIMIT_FSIZE=0 the O_EXCL create succeeds (an empty file) and the write fails
// with EFBIG, the same mechanism as the SecureWriteFile tests in
// securefiles_s24_darwin_test.go. Kills the CONDITIONALS_NEGATION mutants on
// the write error checks at securefiles.go:328 and :343 (gremlins,
// MUTANT-SEC-1), which would otherwise close the file and return nil, leaving a
// truncated key file reported as written.
func TestSecureCreateFile_WriteError_RLIMIT(t *testing.T) {
	base := t.TempDir()
	restore := rlimitFsize(t, 0)
	defer restore()

	err := SecureCreateFile(base, "new.key", []byte("new-secret"), 0o600)
	require.Error(t, err, "a failed Write must not be reported as success")
	restore()
	info, statErr := os.Stat(filepath.Join(base, "new.key"))
	require.NoError(t, statErr)
	require.Zero(t, info.Size())
}

func TestSecureCreateFileSync_WriteError_RLIMIT(t *testing.T) {
	base := t.TempDir()
	restore := rlimitFsize(t, 0)
	defer restore()

	err := SecureCreateFileSync(base, "new.key", []byte("new-secret"), 0o600)
	require.Error(t, err, "a failed Write must not be reported as success")
}
