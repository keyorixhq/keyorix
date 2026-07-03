package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveCLIConfig_RoundTripAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.yaml")

	cfg := DefaultCLIConfig()
	cfg.SetClientMode("https://keyorix.example.com", "kx_api_secret")

	require.NoError(t, SaveCLIConfig(cfg, path))

	// The file must be written with 0600 perms — it can hold an API key — not the
	// world/group-readable 0644 a plain os.WriteFile-without-perm-enforcement risks.
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	loaded, err := LoadCLIConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "client", loaded.Mode)
	assert.Equal(t, "https://keyorix.example.com", loaded.Client.Endpoint)
	assert.Equal(t, "kx_api_secret", loaded.Client.Auth.APIKey)
}

// A dangling final-component symlink at the config path must not be followed: writing
// through it would let a local attacker who can plant a symlink redirect a config
// write (containing an API key) to an arbitrary file outside the intended directory.
func TestSaveCLIConfig_RefusesDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.yaml")
	outside := filepath.Join(filepath.Dir(dir), "escape-cli.yaml")
	require.NoError(t, os.Symlink(outside, path))

	cfg := DefaultCLIConfig()
	err := SaveCLIConfig(cfg, path)
	require.Error(t, err, "writing through a symlink must be refused")

	_, statErr := os.Stat(outside)
	assert.True(t, os.IsNotExist(statErr), "the symlink target outside the config dir must not have been created")
}
