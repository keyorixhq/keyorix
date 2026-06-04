package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Load("") must honour KEYORIX_CONFIG_PATH, including an absolute path (the
// container-deployment case the production compose relies on).
func TestLoadUsesConfigPathEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "production.yaml")
	require.NoError(t, os.WriteFile(p, []byte("locale:\n  language: fr\n"), 0600))

	t.Setenv("KEYORIX_CONFIG_PATH", p)
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "fr", cfg.Locale.Language)
}

// An explicit path argument wins over KEYORIX_CONFIG_PATH.
func TestLoadExplicitPathBeatsEnv(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env.yaml")
	argFile := filepath.Join(dir, "arg.yaml")
	require.NoError(t, os.WriteFile(envFile, []byte("locale:\n  language: fr\n"), 0600))
	require.NoError(t, os.WriteFile(argFile, []byte("locale:\n  language: de\n"), 0600))

	t.Setenv("KEYORIX_CONFIG_PATH", envFile)
	cfg, err := Load(argFile)
	require.NoError(t, err)
	assert.Equal(t, "de", cfg.Locale.Language)
}

// A missing config file returns an error rather than a zero-value config.
func TestLoadMissingFile(t *testing.T) {
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	_, err := Load("")
	require.Error(t, err)
}
