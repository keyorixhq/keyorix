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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withTTYStdin makes os.Stdin the slave of a fresh pty, types input on the master
// (before the read, so it waits in the line discipline's queue) and points os.Stderr
// at a file so the prompt does not clutter the test log. It returns the stderr path
// and the master end (resolveWithDeadline uses it to unblock a read that never ends).
func withTTYStdin(t *testing.T, input string) (stderrPath string, master *os.File) {
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

	if input != "" {
		_, err = master.WriteString(input)
		require.NoError(t, err)
	}
	return stderrPath, master
}

// resolveWithDeadline runs ResolvePassphrase on the pty stdin and fails the test after
// a deadline instead of hanging the package until the go test timeout (CI hung for 30
// minutes on the Ctrl-D case, and a Ctrl-D typed every 50ms still never ended the read
// on the CI runner). If hangup is set, the master is closed once the read is pending:
// the terminal goes away under the prompt, the blocked read returns an error and
// term.ReadPassword reports it. Closing the master is also what unblocks the read on
// deadline.
func resolveWithDeadline(t *testing.T, master *os.File, hangup bool) ([]byte, error) {
	t.Helper()
	type result struct {
		got []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		got, err := ResolvePassphrase(PassphraseSource{Stdin: true}, "UNUSED")
		done <- result{got, err}
	}()
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case r := <-done:
			return r.got, r.err
		case <-tick.C:
			if hangup {
				_ = master.Close()
				hangup = false
			}
		case <-deadline:
			_ = master.Close()
			<-done
			t.Fatal("ResolvePassphrase did not return within 20s on a pty stdin")
			return nil, nil
		}
	}
}

func TestResolvePassphrase_Stdin_Terminal(t *testing.T) {
	t.Run("typed passphrase is returned without its newline, after a prompt", func(t *testing.T) {
		stderrPath, master := withTTYStdin(t, "s3cret pass\n")
		got, err := resolveWithDeadline(t, master, false)
		require.NoError(t, err)
		assert.Equal(t, "s3cret pass", string(got))

		prompt, err := os.ReadFile(stderrPath)
		require.NoError(t, err)
		assert.Contains(t, string(prompt), "Master passphrase: ")
		assert.NotContains(t, string(prompt), "s3cret", "the typed passphrase is never echoed")
	})

	t.Run("an empty entry is refused", func(t *testing.T) {
		_, master := withTTYStdin(t, "\n")
		got, err := resolveWithDeadline(t, master, false)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.EqualError(t, err, "no passphrase entered")
	})

	t.Run("end of input at the prompt is a read error, not an empty passphrase", func(t *testing.T) {
		_, master := withTTYStdin(t, "") // the terminal is hung up while the read waits
		got, err := resolveWithDeadline(t, master, true)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.ErrorContains(t, err, "reading passphrase from terminal: ")
	})
}
