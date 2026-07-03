package secret

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetScanFlags restores the scan command's package-level flag state after a test
// mutates it directly (the flags are cobra package vars, not per-call state).
func resetScanFlags(t *testing.T) {
	t.Helper()
	origCommit, origStaged, origImport, origReport, origSeverity := scanCommit, scanStaged, scanImport, scanReport, scanSeverity
	t.Cleanup(func() {
		scanCommit, scanStaged, scanImport, scanReport, scanSeverity = origCommit, origStaged, origImport, origReport, origSeverity
	})
}

func TestRunScan_CommitFlagRejectsLeadingDash(t *testing.T) {
	resetScanFlags(t)
	dir := t.TempDir()

	// A --commit value starting with "-" would otherwise be parsed by git as a flag
	// (e.g. "--upload-pack=/some/evil") instead of a revision — arg injection. It must
	// be rejected before a git subprocess is ever spawned.
	scanCommit = "--upload-pack=/bin/sh"

	err := runScan(scanCmd, []string{dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --commit value")
}

func TestRunScan_CommitFlagAcceptsARealRevision(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	resetScanFlags(t)
	dir := t.TempDir()

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) // #nosec G204 -- test-controlled args
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t.io", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t.io")
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v: %s", args, out)
	}

	runGit("init", "-q")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("api_key: AKIAABCDEFGHIJKLMNOP\n"), 0600))
	runGit("add", "config.yaml")
	runGit("commit", "-q", "-m", "add config")

	scanCommit = "HEAD"
	err := runScan(scanCmd, []string{dir})
	require.NoError(t, err, "a real revision must still work after the arg-injection fix")
}
