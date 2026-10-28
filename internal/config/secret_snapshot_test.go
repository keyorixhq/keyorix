package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SECRETENV-REVIEW-1 F5/F6 (SECRETENV-TAILS-2 item 4): a *_FILE secret is read
// once at Load, from the descriptor whose permissions are judged; the accessors
// and the boot checks (ValidateSecretSources, ConfiguredSecretValues,
// EnforceSecretFilePermissions, the SCIM strength check through SCIM.GetToken)
// all see those bytes. A file swapped after Load is not what gets used.

// loadWithSCIMTokenFile writes a minimal config, points KEYORIX_SCIM_TOKEN_FILE at
// a file holding content with mode, and loads the config.
func loadWithSCIMTokenFile(t *testing.T, content string, mode os.FileMode) (*Config, string) {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "scim-token")
	require.NoError(t, os.WriteFile(tok, []byte(content), 0o600))
	require.NoError(t, os.Chmod(tok, mode))
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("environment: test\nscim:\n  enabled: true\n"), 0o600))
	t.Setenv("KEYORIX_SCIM_TOKEN", "")
	t.Setenv("KEYORIX_SCIM_TOKEN_FILE", tok)
	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	return cfg, tok
}

// swapFile replaces the file at path with new content and mode (a new inode, the
// way an attacker with write access to the directory would).
func swapFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	tmp := path + ".new"
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0o600))
	require.NoError(t, os.Chmod(tmp, mode))
	require.NoError(t, os.Rename(tmp, path))
}

func strictFilePermissions(cfg *Config) {
	cfg.Security.EnableFilePermissionCheck = true
	cfg.Security.AllowUnsafeFilePermissions = false
	cfg.Security.EnableFilePermissionCheckUpgradeGrace = false
}

const judgedToken = "judged-scim-token-0123456789abcdef0123456789abcdef"
const swappedToken = "swapped-scim-token-fedcba9876543210fedcba9876543210"

func TestSecretSnapshot_FileSwappedAfterLoad_AccessorsUseJudgedValue(t *testing.T) {
	cfg, tok := loadWithSCIMTokenFile(t, judgedToken+"\n", 0o600)
	swapFile(t, tok, swappedToken+"\n", 0o600)

	assert.Equal(t, judgedToken, cfg.SCIM.GetToken(), "the accessor must return the bytes Load read, not the swapped file")
	assert.Equal(t, judgedToken, cfg.SCIM.GetToken(), "and the same bytes on every call")
	assert.Equal(t, judgedToken, cfg.ConfiguredSecretValues()["KEYORIX_SCIM_TOKEN"], "the duplicate-secret check (#3397) must judge the value in use")
	require.NoError(t, cfg.ValidateSecretSources())
}

// F6: permissions judged on the descriptor the value came from, not a later stat.
func TestSecretSnapshot_PermissionVerdictIsTheReadDescriptors(t *testing.T) {
	t.Run("too open at Load, fixed afterwards: still refused", func(t *testing.T) {
		cfg, tok := loadWithSCIMTokenFile(t, judgedToken+"\n", 0o644)
		swapFile(t, tok, swappedToken+"\n", 0o600)
		strictFilePermissions(cfg)
		_, err := cfg.EnforceSecretFilePermissions()
		require.Error(t, err, "the value in use came from a 0644 file; a 0600 file swapped in later must not clear it")
		assert.Contains(t, err.Error(), "KEYORIX_SCIM_TOKEN_FILE=")
		assert.Contains(t, err.Error(), "mode 0644 is too open")
		assert.NotContains(t, err.Error(), judgedToken)
		assert.Equal(t, judgedToken, cfg.SCIM.GetToken(), "the value is the judged one")
	})
	t.Run("0600 at Load, loosened afterwards: the judged value is used", func(t *testing.T) {
		cfg, tok := loadWithSCIMTokenFile(t, judgedToken+"\n", 0o600)
		swapFile(t, tok, swappedToken+"\n", 0o644)
		strictFilePermissions(cfg)
		_, err := cfg.EnforceSecretFilePermissions()
		require.NoError(t, err)
		assert.Equal(t, judgedToken, cfg.SCIM.GetToken(), "the swapped (too-open) file's bytes are never used")
	})
}

// A read failure at Load stays a failure: "" (which server/middleware/scim.go
// refuses every request on, TestSCIMToken_EmptyConfigDeniesAll) and a
// ValidateSecretSources error, even if a readable file appears afterwards.
func TestSecretSnapshot_ReadFailureFailsClosed(t *testing.T) {
	cfg, tok := loadWithSCIMTokenFile(t, "", 0o600) // empty file: unreadable as a secret
	require.Empty(t, cfg.SCIM.GetToken())
	swapFile(t, tok, swappedToken+"\n", 0o600)

	assert.Empty(t, cfg.SCIM.GetToken(), "a file that failed at Load must not be re-read into a usable token")
	err := cfg.ValidateSecretSources()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_SCIM_TOKEN_FILE=")
	assert.Contains(t, err.Error(), "secret file is empty")
	assert.NotContains(t, cfg.ConfiguredSecretValues(), "KEYORIX_SCIM_TOKEN")
}

// The snapshot answers only while the environment names the file it read: a
// changed variable is resolved live, never from a stale entry.
func TestSecretSnapshot_ChangedEnvironmentIsResolvedLive(t *testing.T) {
	cfg, _ := loadWithSCIMTokenFile(t, judgedToken+"\n", 0o600)
	other := filepath.Join(t.TempDir(), "other")
	require.NoError(t, os.WriteFile(other, []byte(swappedToken+"\n"), 0o600))
	t.Setenv("KEYORIX_SCIM_TOKEN_FILE", other)
	assert.Equal(t, swappedToken, cfg.SCIM.GetToken())

	t.Setenv("KEYORIX_SCIM_TOKEN_FILE", "")
	t.Setenv("KEYORIX_SCIM_TOKEN", "direct-value")
	assert.Equal(t, "direct-value", cfg.SCIM.GetToken())
}
