package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveCLIConfig_TightensExistingLoosePermissions pins the #206 fix: SaveCLIConfig
// must tighten a pre-existing, loosely-permissioned config file to 0600 on the next save
// — not just apply the mode on first creation. os.WriteFile's perm argument only applies
// when the file is newly created (O_CREATE|O_TRUNC on an existing file preserves its
// current mode bits), so without an explicit Chmod a config file inherited with a looser
// mode (e.g. restored from a backup/dotfiles-sync/rsync, or written by an older client
// version) would silently keep accepting writes — including a deliberate API-key
// rotation — while remaining world/group readable.
func TestSaveCLIConfig_TightensExistingLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.yaml")

	// Pre-plant the file with loose permissions, as if inherited from before this
	// codebase adopted secure-write conventions.
	require.NoError(t, os.WriteFile(path, []byte("mode: embedded\n"), 0644))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0644), info.Mode().Perm(), "precondition: file starts loosely permissioned")

	cfg := DefaultCLIConfig()
	cfg.SetClientMode("https://keyorix.example", "rotated-api-key")
	require.NoError(t, SaveCLIConfig(cfg, path))

	info, err = os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "SaveCLIConfig must tighten a pre-existing loosely-permissioned file to 0600")

	// The rotated content was actually written, not just the mode fixed.
	loaded, err := LoadCLIConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "rotated-api-key", loaded.Client.Auth.APIKey)
}

// TestSaveCLIConfig_NewFileGetsSecureMode confirms the unexceptional case still holds:
// a brand-new config file is created directly with 0600.
func TestSaveCLIConfig_NewFileGetsSecureMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.yaml")

	require.NoError(t, SaveCLIConfig(DefaultCLIConfig(), path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
