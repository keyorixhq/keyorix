//go:build linux || darwin

package crypto

// The terminal branches of readPassphraseStdin (passphrase.go: the term.ReadPassword
// error and the empty-entry refusal) run only when stdin is a TTY, so these tests give
// the process a pseudo-terminal as os.Stdin (MUTANT-RESIDUAL-1). They skip, with the
// reason, where no pty can be opened.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withTTYStdin makes os.Stdin the slave of a fresh pty, types input on the master
// (before the read, so it waits in the line discipline's queue) and points os.Stderr
// at a file so the prompt does not clutter the test log. It returns the stderr path.
func withTTYStdin(t *testing.T, input string) (stderrPath string) {
	t.Helper()
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("no pty available here: %v", err)
	}
	stderrPath = filepath.Join(t.TempDir(), "stderr")
	errFile, err := os.Create(stderrPath)
	require.NoError(t, err)

	origStdin, origStderr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = slave, errFile
	t.Cleanup(func() {
		os.Stdin, os.Stderr = origStdin, origStderr
		_ = errFile.Close()
		_ = slave.Close()
		_ = master.Close()
	})

	_, err = master.WriteString(input)
	require.NoError(t, err)
	return stderrPath
}

func TestResolvePassphrase_Stdin_Terminal(t *testing.T) {
	t.Run("typed passphrase is returned without its newline, after a prompt", func(t *testing.T) {
		stderrPath := withTTYStdin(t, "s3cret pass\n")
		got, err := ResolvePassphrase(PassphraseSource{Stdin: true}, "UNUSED")
		require.NoError(t, err)
		assert.Equal(t, "s3cret pass", string(got))

		prompt, err := os.ReadFile(stderrPath)
		require.NoError(t, err)
		assert.Contains(t, string(prompt), "Master passphrase: ")
		assert.NotContains(t, string(prompt), "s3cret", "the typed passphrase is never echoed")
	})

	t.Run("an empty entry is refused", func(t *testing.T) {
		withTTYStdin(t, "\n")
		got, err := ResolvePassphrase(PassphraseSource{Stdin: true}, "UNUSED")
		require.Error(t, err)
		assert.Nil(t, got)
		assert.EqualError(t, err, "no passphrase entered")
	})

	t.Run("end of input at the prompt is a read error, not an empty passphrase", func(t *testing.T) {
		withTTYStdin(t, "\x04") // Ctrl-D at the start of a line
		got, err := ResolvePassphrase(PassphraseSource{Stdin: true}, "UNUSED")
		require.Error(t, err)
		assert.Nil(t, got)
		assert.ErrorContains(t, err, "reading passphrase from terminal: ")
	})
}
