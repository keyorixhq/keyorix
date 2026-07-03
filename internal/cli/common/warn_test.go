package common

import (
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStderr redirects os.Stderr for the duration of fn and returns everything
// written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func newCmdWithFlag(flagName, value string, changed bool) *cobra.Command {
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().String(flagName, "", "")
	if changed {
		_ = cmd.Flags().Set(flagName, value)
	}
	return cmd
}

func TestWarnInsecureFlag(t *testing.T) {
	t.Run("warns when the flag was explicitly set on the command line", func(t *testing.T) {
		cmd := newCmdWithFlag("value", "s3cr3t", true)
		out := captureStderr(t, func() {
			WarnInsecureFlag(cmd, "value", "use --interactive instead.")
		})
		assert.Contains(t, out, "--value")
		assert.Contains(t, out, "ps/proc")
		assert.Contains(t, out, "shell history")
		assert.Contains(t, out, "use --interactive instead.")
	})

	t.Run("stays silent when the flag was left at its default", func(t *testing.T) {
		cmd := newCmdWithFlag("value", "", false)
		out := captureStderr(t, func() {
			WarnInsecureFlag(cmd, "value", "use --interactive instead.")
		})
		assert.Empty(t, out, "no warning should be printed when the insecure flag was never used")
	})
}
