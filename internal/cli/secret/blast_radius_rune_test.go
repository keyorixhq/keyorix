// blast_radius_rune_test.go — exercises blastRadiusCmd.RunE directly
// (blast_radius_test.go tests fetchBlastRadius/printBlastRadius/blastRadiusClient
// individually, never the command closure that wires them together).
package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlastRadiusCmd_Success(t *testing.T) {
	_, done := blastRadiusStub(t)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := blastRadiusCmd.RunE(blastRadiusCmd, []string{"7"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "db-password")
	assert.Contains(t, out, "app-token")
}

func TestBlastRadiusCmd_NoDependents(t *testing.T) {
	_, done := blastRadiusStub(t)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := blastRadiusCmd.RunE(blastRadiusCmd, []string{"8"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No dependents")
}

func TestBlastRadiusCmd_InvalidArg(t *testing.T) {
	err := blastRadiusCmd.RunE(blastRadiusCmd, []string{"0"})
	require.Error(t, err)
}

func TestBlastRadiusCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := blastRadiusCmd.RunE(blastRadiusCmd, []string{"7"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestBlastRadiusCmd_FetchError(t *testing.T) {
	_, done := blastRadiusStub(t)
	defer done()
	err := blastRadiusCmd.RunE(blastRadiusCmd, []string{"9999"})
	require.Error(t, err)
}
