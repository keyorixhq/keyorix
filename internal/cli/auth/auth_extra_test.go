package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskAPIKey_Short(t *testing.T) {
	assert.Equal(t, "***", maskAPIKey("short"))
}

func TestMaskAPIKey_Long(t *testing.T) {
	assert.Equal(t, "kx_a...cret", maskAPIKey("kx_averylongsecret"))
}

func TestAuthCmdStructure(t *testing.T) {
	names := make(map[string]bool)
	for _, c := range AuthCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"login", "logout", "status"} {
		assert.True(t, names[expected], "expected subcommand %q", expected)
	}
}

func TestLoginCmd_HasExpectedFlags(t *testing.T) {
	for _, f := range []string{"api-key", "server"} {
		assert.NotNil(t, loginCmd.Flags().Lookup(f), "login should have --%s flag", f)
	}
}
