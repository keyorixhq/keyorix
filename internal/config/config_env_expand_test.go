package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// server/config/production.yaml documents ${VAR:-default} shell-style interpolation for
// server.http.domain/allowed_origins, but the loader used to do a plain yaml.Unmarshal
// with no expansion step — the documented syntax silently became the literal string
// "${KEYORIX_DOMAIN:-localhost}" instead of resolving. These tests exercise Load()'s
// expandEnvVars preprocessing end to end, covering the var-set and var-unset/default
// cases the documented syntax relies on.

// When the referenced environment variable is set (and non-empty), its value is used —
// the default is ignored, matching bash's ${VAR:-default} semantics.
func TestLoadExpandsEnvVarWhenSet(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(
		"server:\n  http:\n    domain: \"${KEYORIX_DOMAIN:-localhost}\"\n    allowed_origins:\n      - \"https://${KEYORIX_DOMAIN:-localhost}\"\n",
	), 0600))

	t.Setenv("KEYORIX_DOMAIN", "secrets.example.com")
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "secrets.example.com", cfg.Server.HTTP.Domain)
	assert.Equal(t, []string{"https://secrets.example.com"}, cfg.Server.HTTP.AllowedOrigins)
}

// When the referenced environment variable is unset, the ":-default" fallback is used —
// the documented "sane default for local/dev" behavior.
func TestLoadExpandsEnvVarFallsBackToDefaultWhenUnset(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(
		"server:\n  http:\n    domain: \"${KEYORIX_DOMAIN:-localhost}\"\n",
	), 0600))

	t.Setenv("KEYORIX_DOMAIN", "") // ensure not set from the outer environment
	os.Unsetenv("KEYORIX_DOMAIN")
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "localhost", cfg.Server.HTTP.Domain)
}

// bash ${VAR:-default} semantics: an explicitly-empty variable also falls back to the
// default, not to an empty string.
func TestLoadExpandsEnvVarFallsBackToDefaultWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(
		"server:\n  http:\n    domain: \"${KEYORIX_DOMAIN:-localhost}\"\n",
	), 0600))

	t.Setenv("KEYORIX_DOMAIN", "")
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "localhost", cfg.Server.HTTP.Domain)
}

// A reference with no default whose variable is unset is left unresolved rather than
// silently collapsed to "" — a missing required value should fail loudly downstream
// (e.g. as an obviously-wrong domain), not disappear.
func TestLoadLeavesUnresolvedEnvVarWithNoDefaultIntact(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(
		"server:\n  http:\n    domain: \"${KEYORIX_REQUIRED_DOMAIN}\"\n",
	), 0600))

	os.Unsetenv("KEYORIX_REQUIRED_DOMAIN")
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "${KEYORIX_REQUIRED_DOMAIN}", cfg.Server.HTTP.Domain)
}

// production.yaml itself must still load cleanly and resolve its documented
// KEYORIX_DOMAIN interpolation end to end.
func TestLoadProductionYAMLExpandsDomain(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	require.NoError(t, err)
	p := filepath.Join(repoRoot, "server", "config", "production.yaml")
	if _, statErr := os.Stat(p); statErr != nil {
		t.Skipf("production.yaml not found at %s: %v", p, statErr)
	}

	t.Setenv("KEYORIX_DOMAIN", "vault.example.com")
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "vault.example.com", cfg.Server.HTTP.Domain)
	assert.Contains(t, cfg.Server.HTTP.AllowedOrigins, "https://vault.example.com")
	assert.Contains(t, cfg.Server.HTTP.AllowedOrigins, "https://www.vault.example.com")
	assert.NotEmpty(t, cfg.Server.HTTP.TrustedProxies, "production.yaml should document a trusted_proxies example")
}
