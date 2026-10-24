package securefiles

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unixOctalMode is a pure function; the setuid/setgid/sticky rows pin each bit
// to its own digit so no branch of the renderer can be flipped unnoticed.
// Kills the CONDITIONALS_NEGATION mutants at securefiles.go:467 and :476
// (gremlins, MUTANT-SEC-1): the existing special-bit tests need a filesystem
// that accepts the bit and are skipped where it does not.
func TestUnixOctalMode_SpecialBits(t *testing.T) {
	cases := []struct {
		name string
		mode os.FileMode
		want string
	}{
		{"plain", 0o600, "600"},
		{"plain 0644", 0o644, "644"},
		{"setuid only", os.ModeSetuid | 0o600, "4600"},
		{"setgid only", os.ModeSetgid | 0o600, "2600"},
		{"sticky only", os.ModeSticky | 0o600, "1600"},
		{"setuid+setgid", os.ModeSetuid | os.ModeSetgid | 0o755, "6755"},
		{"all three", os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0o755, "7755"},
		{"type bits are not special bits", os.ModeDir | 0o700, "700"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, unixOctalMode(tc.mode))
		})
	}
}

// SyncDir on a directory that does not exist must return the open error itself,
// not a later error from syncing a nil handle. Kills the CONDITIONALS_NEGATION
// mutant at securefiles.go:394.
func TestSyncDir_MissingDir_ReturnsOpenError(t *testing.T) {
	err := SyncDir(filepath.Join(t.TempDir(), "absent"))
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// A file owned by someone else, with autofix on, must produce an error when the
// chown cannot be performed, not a "[FIXED]" line and a nil return. /etc/hosts
// is root-owned and world-readable on every Linux and macOS host, and its mode
// is passed as the expected mode so only the ownership branch is exercised.
// Kills the CONDITIONALS_NEGATION mutant at securefiles.go:570 (the chown
// error check), which was NOT COVERED before: no test reached the branch.
func TestFixFilePerms_AutofixChownFailure_IsUnresolved(t *testing.T) {
	const path = "/etc/hosts"
	cur, err := user.Current()
	require.NoError(t, err)
	if cur.Uid == "0" {
		t.Skip("running as root: chown to self succeeds, the failure branch is unreachable")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Skipf("%s not available: %v", path, err)
	}

	err = FixFilePerms([]FilePermSpec{{Path: path, Mode: info.Mode().Perm()}}, true)
	require.Error(t, err, "a chown that fails must leave the audit unresolved")
	assert.Contains(t, err.Error(), "chown failed")
}
