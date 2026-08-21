// main_s25_test.go — coverage sprint s25 for internal/cli/main.go.
//
// Targets the one remaining branch in Execute() that main_test.go and
// modes_s24_test.go don't reach: the rootCmd.Execute() error path, which
// prints the error to stderr and calls os.Exit(1). That os.Exit(1) would
// kill the test binary if invoked in-process, so this uses the standard Go
// "re-exec the test binary as a subprocess" pattern (the same technique
// os/exec's own tests use for TestHelperProcess) to observe the exit code
// and stderr output from outside the process.
package cli

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecute_UnknownCommand_ExitsNonZero_Helper is not a real test on its
// own — when run directly (KEYORIX_TEST_EXECUTE_HELPER=1) it drives Execute()
// with an unknown subcommand so rootCmd.Execute() returns an error, which
// exercises the fmt.Fprintln(os.Stderr, err) + os.Exit(1) branch in Execute.
// TestExecute_UnknownCommand_ExitsNonZero (below) re-invokes this test as a
// subprocess and asserts on the resulting exit code / stderr.
func TestExecute_UnknownCommand_ExitsNonZero_Helper(t *testing.T) {
	if os.Getenv("KEYORIX_TEST_EXECUTE_HELPER") != "1" {
		t.Skip("only runs as a subprocess helper; see TestExecute_UnknownCommand_ExitsNonZero")
	}
	rootCmd.SetArgs([]string{"this-command-does-not-exist-s25"})
	Execute()
	// Execute() must call os.Exit(1) before reaching here when the command is
	// unknown; if it doesn't, the parent test will see exit code 0 and fail.
}

// TestExecute_UnknownCommand_ExitsNonZero drives Execute()'s error path (the
// branch main_test.go and modes_s24_test.go leave uncovered): an unknown
// subcommand makes rootCmd.Execute() return a non-nil error, which Execute
// must print to stderr and turn into a process exit code of 1 (not a panic,
// not exit 0). Runs the test binary as a subprocess because os.Exit(1)
// cannot be observed from within the same process that calls it.
func TestExecute_UnknownCommand_ExitsNonZero(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecute_UnknownCommand_ExitsNonZero_Helper$", "-test.v")
	cmd.Env = append(os.Environ(), "KEYORIX_TEST_EXECUTE_HELPER=1")
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	err := cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "Execute() must exit non-zero on an unknown command, not exit 0 or panic")
	assert.Equal(t, 1, exitErr.ExitCode(), "Execute() must exit with code 1 on rootCmd.Execute() error")
	assert.Contains(t, stderr.String(), "this-command-does-not-exist-s25",
		"Execute() must print the rootCmd.Execute() error (which names the unknown command) to stderr")
}
