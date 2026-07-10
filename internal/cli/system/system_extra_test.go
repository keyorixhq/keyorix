package system

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemCmdStructure(t *testing.T) {
	assert.Equal(t, "system", SystemCmd.Use)
	names := make(map[string]bool)
	for _, c := range SystemCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"init", "audit", "validate", "info"} {
		assert.True(t, names[expected], "expected subcommand %q to be registered", expected)
	}
}

func TestValidateCmd_Flags(t *testing.T) {
	assert.NotNil(t, validateCmd.Flags().Lookup("config"))
	assert.NotNil(t, validateCmd.Flags().Lookup("fix"))
}

func TestRunValidate_ConfigFileNotFound(t *testing.T) {
	orig := configFile
	defer func() { configFile = orig }()
	configFile = filepath.Join(t.TempDir(), "does-not-exist.yaml")

	err := runValidate(validateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config file not found")
}

// When the config file exists the validation will run through startup.ValidateStartup.
// That requires a real keyorix.yaml with valid fields; we don't spin that up here —
// a file that exists but is empty/minimal is enough to confirm the path proceeds
// past the os.Stat check and into the startup layer (which produces its own error or
// result). We just confirm no panic and that the "config file not found" guard is
// not triggered.
func TestRunValidate_ConfigFileExists_NoPanicOnBadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(path, []byte("storage:\n  type: sqlite\n"), 0o600))

	orig := configFile
	defer func() { configFile = orig }()
	configFile = path

	// May succeed or fail depending on startup.ValidateStartup behavior, but must not panic
	// and must not return the "config file not found" sentinel.
	err := runValidate(validateCmd, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "config file not found")
	}
}

func TestSystemInfoCmd_HasSilenceUsage(t *testing.T) {
	cmd, _, err := SystemCmd.Find([]string{"info"})
	require.NoError(t, err)
	assert.True(t, cmd.SilenceUsage)
}
