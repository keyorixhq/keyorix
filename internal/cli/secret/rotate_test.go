package secret

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
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

// TestRunRotate_HungServerTimesOut is the #G71 detection-idea regression test:
// point the configured server at a listener that accepts the TCP connection but
// never writes a response, and assert runRotate fails with a bounded timeout
// error rather than hanging indefinitely — matching common.RemoteClient's own
// defaultRemoteClientTimeout (30s), since runRotate now goes through
// common.NewRemoteClient instead of its own bypassing *http.Client.
//
// The endpoint is set BOTH via KEYORIX_SERVER/KEYORIX_TOKEN (what the current,
// fixed runRotate reads via common.ResolveRemote) AND via a written cli.yaml
// (what the pre-fix runRotate read directly via cliconfig.LoadCLIConfig) so this
// same test reproduces the hang against either implementation — confirmed to
// hang past this test's own outer bound when run against the pre-#G71 rotate.go
// (env vars alone are silently ignored by that code path, which would otherwise
// make the test fail fast on an unrelated "unsupported protocol scheme" error
// instead of genuinely exercising the hang).
func TestRunRotate_HungServerTimesOut(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	resetRotateFlags(t)
	require.NoError(t, rotateCmd.Flags().Set("value", "new-rotated-value"))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck

	// Accept connections but never read/write/close them — simulates a hung or
	// malicious KEYORIX_SERVER that completes the TCP handshake and then stalls.
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c // deliberately leaked for the test's duration; never responded to
		}
	}()
	endpoint := "http://" + ln.Addr().String()
	t.Setenv("KEYORIX_SERVER", endpoint)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	cliCfg := cliconfig.DefaultCLIConfig()
	cliCfg.Mode = "client"
	cliCfg.Client.Endpoint = endpoint
	cliCfg.Client.Auth = cliconfig.AuthConfig{Type: "api_key", APIKey: "test-token"}
	require.NoError(t, cliconfig.SaveCLIConfig(cliCfg, filepath.Join(dir, "keyorix", "cli.yaml")))

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- runRotate(rotateCmd, []string{"some-secret"})
	}()

	// Generous outer bound well above the 30s client timeout so this isn't flaky,
	// but still bounded so a regression to an unbounded hang fails the test instead
	// of hanging the suite forever.
	const outerBound = 55 * time.Second
	select {
	case err := <-done:
		elapsed := time.Since(start)
		require.Error(t, err, "a hung server must surface a timeout error, not succeed or hang")
		assert.Less(t, elapsed, outerBound, "runRotate must return close to the remote client's own request timeout, not hang indefinitely")
	case <-time.After(outerBound):
		t.Fatal("runRotate hung indefinitely against an unresponsive server (#G71): 'secret rotate' is missing common.RemoteClient's request timeout")
	}
}

func TestRotateCmd_ValueFlagIsNotRequired(t *testing.T) {
	f := rotateCmd.Flags().Lookup("value")
	require.NotNil(t, f)
	assert.Empty(t, f.Annotations[requiredFlagAnnotation], "--value must be optional now that omitting it prompts interactively")
}

const requiredFlagAnnotation = "cobra_annotation_bash_completion_one_required_flag"
