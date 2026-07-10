package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskAPIKey_Short(t *testing.T) {
	assert.Equal(t, "***", maskAPIKey("12345678"))
}

func TestMaskAPIKey_Long(t *testing.T) {
	assert.Equal(t, "kx_a...cret", maskAPIKey("kx_averylongsecret"))
}

func TestConfigCmdStructure(t *testing.T) {
	names := make(map[string]bool)
	for _, c := range ConfigCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"status", "set-remote", "use-local", "test-connection"} {
		assert.True(t, names[expected], "expected subcommand %q", expected)
	}
}

func TestSetRemoteCmd_HasExpectedFlags(t *testing.T) {
	for _, f := range []string{"url", "api-key", "timeout"} {
		assert.NotNil(t, setRemoteCmd.Flags().Lookup(f), "set-remote should have --%s flag", f)
	}
}

func TestSetRemoteCmd_URLIsRequired(t *testing.T) {
	const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"
	f := setRemoteCmd.Flags().Lookup("url")
	require.NotNil(t, f)
	assert.NotEmpty(t, f.Annotations[cobraRequired])
}
