package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBootstrapI18n_HonorsConfiguredLocale is the regression test for the bug
// this file's Execute() used to have: it called i18n.InitializeForTesting()
// (hardcoded English) before rootCmd.Execute() ran any subcommand. Because
// i18n.Initialize is guarded by a package-level sync.Once, that eager,
// hardcoded call always won the race, and every subcommand's later, correctly
// -configured call (common.InitializeCoreService -> i18n.Initialize(cfg))
// silently became a no-op — a non-English locale in keyorix.yaml was never
// honored by the shipped CLI binary. bootstrapI18n (extracted from Execute)
// must load the real config and initialize i18n from it, so this proves a
// configured non-English locale actually takes effect.
func TestBootstrapI18n_HonorsConfiguredLocale(t *testing.T) {
	i18n.ResetForTesting()
	t.Cleanup(i18n.ResetForTesting)

	dir := t.TempDir()
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	// config.Save always resolves its path arg relative to "." (unlike
	// config.Load, which special-cases an absolute path) — chdir into the temp
	// dir and use a bare relative filename, matching the existing convention in
	// integration_test.go's tests, rather than passing an absolute path.
	require.NoError(t, config.Save("keyorix.yaml", &config.Config{
		Locale: config.LocaleConfig{Language: "es", FallbackLanguage: "en"},
	}))

	require.NoError(t, bootstrapI18n())

	assert.Equal(t, "Error de validación", i18n.T("ErrorValidation", nil),
		"the configured locale (es) must be the ACTIVE one, not the English default")
}

// TestBootstrapI18n_FallsBackToEnglishWithNoConfig proves the no-config-file
// path (first run, or KEYORIX_CONFIG_PATH pointing nowhere) still leaves i18n
// usable rather than leaving GetLocalizer() to panic on the first T() call.
func TestBootstrapI18n_FallsBackToEnglishWithNoConfig(t *testing.T) {
	i18n.ResetForTesting()
	t.Cleanup(i18n.ResetForTesting)

	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(t.TempDir(), "does-not-exist.yaml"))

	require.NoError(t, bootstrapI18n())
	assert.Equal(t, "Validation error", i18n.T("ErrorValidation", nil))
}

func TestCLIMode_String(t *testing.T) {
	tests := []struct {
		mode CLIMode
		want string
	}{
		{EmbeddedMode, "embedded"},
		{ClientMode, "client"},
		{CLIMode(99), "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.mode.String())
	}
}

// TestCLI_Health_NoCoreService proves Health fails cleanly (not a nil-pointer
// panic) when called on a CLI whose mode initialization never ran or failed —
// e.g. a future code path that constructs CLI directly.
func TestCLI_Health_NoCoreService(t *testing.T) {
	c := &CLI{}
	err := c.Health(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "core service not initialized")
}

func TestCLI_Getters(t *testing.T) {
	c := &CLI{mode: ClientMode}
	assert.Equal(t, ClientMode, c.GetMode())
	assert.Nil(t, c.GetConfig())
	assert.Nil(t, c.GetCoreService())
}

// TestNewCLI_EmbeddedMode_DefaultsToLocalSQLite drives the real NewCLI() /
// initializeMode() / detectMode() / initEmbeddedMode() path end to end: no CLI
// config file present (XDG_CONFIG_HOME points at an empty temp dir) must
// resolve to embedded mode against a local SQLite-backed core service that
// actually answers a health check.
func TestNewCLI_EmbeddedMode_DefaultsToLocalSQLite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	c, err := NewCLI()
	require.NoError(t, err)
	assert.Equal(t, EmbeddedMode, c.GetMode())
	require.NotNil(t, c.GetCoreService())
	assert.NoError(t, c.Health(context.Background()))
}

// TestNewCLI_ClientMode_MissingEndpoint_Errors proves initClientMode's
// validation actually gates NewCLI: a CLI config in "client" mode with no
// endpoint set must fail construction with a clear error, not proceed with a
// CLI that silently has no usable core service.
func TestNewCLI_ClientMode_MissingEndpoint_Errors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keyorix"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix", "cli.yaml"),
		[]byte("mode: client\n"), 0o600))

	_, err := NewCLI()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client endpoint is required")
}
