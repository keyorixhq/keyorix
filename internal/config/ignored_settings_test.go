package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The never-read secrets.* keys still load (old configs keep booting) but each
// one present produces a start-up deprecation warning (ignoredSettingPaths).
func TestLoad_IgnoredSecretsKeysWarnButLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(
		"secrets:\n  chunking:\n    enabled: true\n    max_chunk_size_kb: 64\n  limits:\n    max_secrets_per_user: 1000\n",
	), 0600))

	cfg, err := Load(p)
	require.NoError(t, err)
	joined := strings.Join(cfg.DeprecatedSettingWarnings, "\n")
	require.Contains(t, joined, `"secrets.chunking" is deprecated and ignored`)
	require.Contains(t, joined, `"secrets.limits.max_secrets_per_user" is deprecated and ignored`)
}

func TestLoad_NoIgnoredKeysNoWarning(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte("secrets:\n  limits:\n    max_secret_size: 65536\n"), 0600))

	cfg, err := Load(p)
	require.NoError(t, err)
	for _, w := range cfg.DeprecatedSettingWarnings {
		require.NotContains(t, w, "deprecated and ignored")
	}
}
