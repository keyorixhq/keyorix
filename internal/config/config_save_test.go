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
