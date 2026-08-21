package license

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetDefaultRegistryFn saves and restores defaultRegistryFn, mirroring the same helper
// in internal/cli/bundle — defaultRegistryFn is package-global state shared across tests.
func resetDefaultRegistryFn(t *testing.T) {
	t.Helper()
	orig := defaultRegistryFn
	t.Cleanup(func() { defaultRegistryFn = orig })
}

// TestInstall_RegistryLoadError covers the "load trusted keys" error branch in
// installCmd.RunE: when defaultRegistryFn itself fails (e.g. a malformed embedded key
// spec — a build/release misconfiguration), install must surface that error verbatim and
// must not attempt to evaluate or write the token.
func TestInstall_RegistryLoadError(t *testing.T) {
	resetDefaultRegistryFn(t)
	defaultRegistryFn = func() (*trust.KeyRegistry, error) {
		return nil, fmt.Errorf("simulated registry failure")
	}

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "empty.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(""), 0o600))

	installDest = filepath.Join(dir, "installed.token")
	installDeployment = ""
	installGraceHours = 0
	t.Cleanup(func() { installDest, installDeployment, installGraceHours = "", "", 0 })

	err := installCmd.RunE(nil, []string{tokenFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load trusted keys")
	assert.Contains(t, err.Error(), "simulated registry failure")
	_, statErr := os.Stat(installDest)
	assert.True(t, os.IsNotExist(statErr), "a registry-load failure must not write the token")
}

// TestStatus_RegistryLoadError covers the same branch in statusCmd.RunE.
func TestStatus_RegistryLoadError(t *testing.T) {
	resetDefaultRegistryFn(t)
	defaultRegistryFn = func() (*trust.KeyRegistry, error) {
		return nil, fmt.Errorf("simulated registry failure")
	}

	statusFile = ""
	statusDeployment = ""
	statusGraceHours = 0
	t.Cleanup(func() { statusFile, statusDeployment, statusGraceHours = "", "", 0 })

	err := statusCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load trusted keys")
	assert.Contains(t, err.Error(), "simulated registry failure")
}
