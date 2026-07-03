package secret

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateCLIConfig points the CLI config lookup at an empty temp dir so
// cliconfig.LoadCLIConfig("") deterministically returns the zero-value default
// (Client.Endpoint == "") regardless of what the host running the tests has on disk.
func isolateCLIConfig(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// resetRotateFlags restores rotateCmd's flag values/Changed state after a test
// mutates them directly.
func resetRotateFlags(t *testing.T) {
	t.Helper()
	origValue, origEnv := rotateValue, rotateEnv
	t.Cleanup(func() {
		rotateValue, rotateEnv = origValue, origEnv
		_ = rotateCmd.Flags().Set("value", "")
		rotateCmd.Flags().Lookup("value").Changed = false
	})
}

func TestRunRotate_ValueFlagWarnsOnCommandLine(t *testing.T) {
	isolateCLIConfig(t)
	resetRotateFlags(t)
	require.NoError(t, rotateCmd.Flags().Set("value", "s3cr3t-on-argv"))

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	// runRotate will go on to fail on the network call (no server configured); that's
	// fine — we only care that the warning was printed before it gets there.
	_ = runRotate(rotateCmd, []string{"some-secret"})
	os.Stderr = origStderr
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Contains(t, string(out), "--value")
	assert.Contains(t, string(out), "ps/proc")
}

// When --value is omitted, rotate must not silently proceed with an empty secret: it
// falls back to an interactive masked prompt, and if that prompt cannot be read (e.g.
// stdin is not a terminal, as in this test), the command must fail closed rather than
// send an empty rotation value to the server.
func TestRunRotate_MissingValueFailsClosedWithoutATerminal(t *testing.T) {
	isolateCLIConfig(t)
	resetRotateFlags(t)

	origStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()
	_ = w.Close() // EOF immediately — simulates a non-interactive/non-tty stdin

	err = runRotate(rotateCmd, []string{"some-secret"})
	require.Error(t, err, "must not proceed with an empty/unread secret value")
}

func TestRotateCmd_ValueFlagIsNotRequired(t *testing.T) {
	f := rotateCmd.Flags().Lookup("value")
	require.NotNil(t, f)
	assert.Empty(t, f.Annotations[requiredFlagAnnotation], "--value must be optional now that omitting it prompts interactively")
}

const requiredFlagAnnotation = "cobra_annotation_bash_completion_one_required_flag"
