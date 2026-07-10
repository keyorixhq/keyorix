//go:build darwin

package securefiles

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFixFilePerms_ChmodError exercises the os.Chmod error path during autofix
// by marking a file user-immutable (macOS uchg flag) before calling FixFilePerms.
func TestFixFilePerms_ChmodError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chmod even immutable files")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "immutable.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0644))
	require.NoError(t, os.Chmod(p, 0644))

	// Set user-immutable flag (UF_IMMUTABLE = 0x00000002 on macOS).
	const ufImmutable = 0x00000002
	require.NoError(t, syscall.Chflags(p, ufImmutable))
	t.Cleanup(func() {
		_ = syscall.Chflags(p, 0)
	})

	err := FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, true)
	require.Error(t, err, "FixFilePerms must return an error when chmod on an immutable file fails")
}
