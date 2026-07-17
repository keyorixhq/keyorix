package di

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// restoreWD returns a cleanup function that restores the working directory to
// whatever it was when restoreWD was called. Always defer the result.
func restoreWD(t *testing.T) func() {
	t.Helper()
	orig, err := os.Getwd()
	require.NoError(t, err, "failed to capture working directory")
	return func() {
		if err := os.Chdir(orig); err != nil {
			t.Errorf("failed to restore working directory to %q: %v", orig, err)
		}
	}
}

// TestInitializeApp_S23_ErrorWhenNoConfigFile verifies that InitializeApp
// returns a non-nil error when keyorix.yaml is absent from the working
// directory. config.Load("keyorix.yaml") resolves to "./keyorix.yaml", so
// running from an empty temp directory is sufficient to exercise the failure
// path without side effects on the real source tree.
func TestInitializeApp_S23_ErrorWhenNoConfigFile(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(restoreWD(t))
	require.NoError(t, os.Chdir(dir))

	result, err := InitializeApp()
	require.Error(t, err, "InitializeApp must fail when keyorix.yaml is missing")
	assert.Empty(t, result, "returned string must be empty on error")
}

// TestInitializeApp_S23_SuccessWithMinimalConfig verifies that InitializeApp
// returns a non-empty result string and no error when a minimal (but valid)
// keyorix.yaml is present in the working directory.
func TestInitializeApp_S23_SuccessWithMinimalConfig(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(restoreWD(t))

	// Write the smallest YAML that config.Load accepts: an empty mapping is
	// valid YAML and leaves all Config fields at their zero values, which is
	// sufficient for Load to succeed (Validate is not called by InitializeApp).
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("{}\n"), 0o600))

	require.NoError(t, os.Chdir(dir))

	result, err := InitializeApp()
	require.NoError(t, err, "InitializeApp must succeed with a valid keyorix.yaml")
	assert.NotEmpty(t, result, "returned string must be non-empty on success")
}

// TestInitializeApp_S23_ErrorPropagatesFromLoad confirms that the error
// returned by InitializeApp on a missing config wraps the underlying file-read
// failure rather than being a generic "unknown error", giving operators an
// actionable message.
func TestInitializeApp_S23_ErrorPropagatesFromLoad(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(restoreWD(t))
	require.NoError(t, os.Chdir(dir))

	_, err := InitializeApp()
	require.Error(t, err)
	// The config.Load wrapper includes the path in the error message.
	assert.Contains(t, err.Error(), "keyorix.yaml",
		"error message should identify the missing config file")
}
