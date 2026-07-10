package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveEnforcesPermsOnExistingFile pins the #296 fix: Save() must tighten a
// pre-existing keyorix.yaml's mode to 0600 rather than silently leaving a looser
// mode in place. appRootDir is "." (the process's working directory), so the
// test chdirs into a scratch directory to keep the write contained.
func TestSaveEnforcesPermsOnExistingFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	const relPath = "keyorix.yaml"
	require.NoError(t, os.WriteFile(filepath.Join(dir, relPath), []byte("old: true\n"), 0644))

	require.NoError(t, Save(relPath, &Config{Environment: "test"}))

	info, err := os.Stat(filepath.Join(dir, relPath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestSaveHonorsAbsolutePath is the regression test for Save's absolute-path
// handling: unlike Load (which already special-cases filepath.IsAbs by
// rooting at the path's own directory), Save used to always join its path arg
// against appRootDir ("."). filepath.Join(".", "/tmp/x/keyorix.yaml") collapses
// to the RELATIVE "tmp/x/keyorix.yaml" under the working directory — so a
// caller passing an absolute path (e.g. KEYORIX_CONFIG_PATH in a container
// deployment) got a file silently written to the wrong place, not an error and
// not the intended location. Save into an absolute path OUTSIDE the current
// working directory and confirm the file lands exactly there, round-trips via
// Load, and nothing was written under cwd instead.
func TestSaveHonorsAbsolutePath(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	elsewhere := t.TempDir()
	absPath := filepath.Join(elsewhere, "keyorix.yaml")

	require.NoError(t, Save(absPath, &Config{Environment: "prod-abs-path-test"}))

	loaded, err := Load(absPath)
	require.NoError(t, err)
	assert.Equal(t, "prod-abs-path-test", loaded.Environment)

	// Must not have been misplaced under cwd as a relative path.
	_, err = os.Stat(filepath.Join(cwd, "tmp"))
	assert.True(t, os.IsNotExist(err), "Save must not create a mangled relative path under cwd")
	entries, err := os.ReadDir(cwd)
	require.NoError(t, err)
	assert.Empty(t, entries, "cwd must remain untouched when Save is given an absolute path")
}
