package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

// An absent session block falls back to the historic 24h access window and no
// absolute ceiling, so existing installs keep their old behaviour.
func TestSessionConfigDefaults(t *testing.T) {
	var c SessionConfig // zero value = block absent
	assert.Equal(t, 24*time.Hour, c.GetAccessTTL())
	assert.Equal(t, time.Duration(0), c.GetAbsoluteTTL(), "no ceiling by default")
}

// A configured session block is parsed; invalid/non-positive values fall back to
// the access-TTL default and to "no ceiling" respectively.
func TestSessionConfigParsing(t *testing.T) {
	c := SessionConfig{AccessTTL: "30m", AbsoluteTTL: "12h"}
	assert.Equal(t, 30*time.Minute, c.GetAccessTTL())
	assert.Equal(t, 12*time.Hour, c.GetAbsoluteTTL())

	bad := SessionConfig{AccessTTL: "nonsense", AbsoluteTTL: "nonsense"}
	assert.Equal(t, 24*time.Hour, bad.GetAccessTTL(), "invalid access TTL → default")
	assert.Equal(t, time.Duration(0), bad.GetAbsoluteTTL(), "invalid absolute TTL → no ceiling")

	zero := SessionConfig{AbsoluteTTL: "0"}
	assert.Equal(t, time.Duration(0), zero.GetAbsoluteTTL(), `"0" → no ceiling`)
}
