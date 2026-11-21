package admin

// REVIEW-4553-DEEP-1 M1(b): an interrupted `verify-audit --db` removes the
// private copy of the database it verifies (removeCopyOnSignal).

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const signalChildEnv = "KEYORIX_TEST_VERIFY_AUDIT_SIGNAL_CHILD_DB"

// An interrupted `verify-audit --db` removes its private copy: the child runs
// runVerifyAudit on a WAL-mode database, holds after the open, and is sent
// SIGINT; it must exit 130 with no keyorix-audit-verify-* left in its TMPDIR.
func TestVerifyAudit_DBCopyRemovedOnSIGINT(t *testing.T) {
	if dbPath := os.Getenv(signalChildEnv); dbPath != "" {
		runVerifyAuditSignalChild(t, dbPath)
		return
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedWALCheckpointedDB(t, dbPath)
	childTmp := filepath.Join(dir, "tmp")
	require.NoError(t, os.Mkdir(childTmp, 0o700))

	cmd := exec.Command(os.Args[0], "-test.run=^TestVerifyAudit_DBCopyRemovedOnSIGINT$", "-test.count=1") // #nosec G204 -- re-runs this test binary
	cmd.Env = append(os.Environ(), signalChildEnv+"="+dbPath, "TMPDIR="+childTmp)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "VERIFY-AUDIT-CHILD-READY") {
				ready <- true
				break
			}
		}
		close(ready)
		for sc.Scan() { // drain, so the child never blocks on a full pipe
		}
	}()
	select {
	case ok := <-ready:
		require.True(t, ok, "child exited before it opened the database")
	case <-time.After(60 * time.Second):
		t.Fatal("child did not reach the hold point within 60s")
	}
	require.Len(t, copyDirs(t, childTmp), 1, "test premise: the child verifies a private copy under its TMPDIR")

	require.NoError(t, cmd.Process.Signal(os.Interrupt))
	waitErr := cmd.Wait()
	var exitErr *exec.ExitError
	require.True(t, errors.As(waitErr, &exitErr), "child exit: %v", waitErr)
	require.Equal(t, 130, exitErr.ExitCode())
	require.Empty(t, copyDirs(t, childTmp), "private copy left in TMPDIR after SIGINT")
}

func runVerifyAuditSignalChild(t *testing.T, dbPath string) {
	resetVerifyAuditAndExportFlags(t)
	configPathFlag = filepath.Join(filepath.Dir(dbPath), "never-written.yaml")
	verifyAuditDBPath = dbPath
	orig := verifyAuditBeforeVerifyHook
	t.Cleanup(func() { verifyAuditBeforeVerifyHook = orig })
	verifyAuditBeforeVerifyHook = func() {
		_, _ = os.Stdout.WriteString("VERIFY-AUDIT-CHILD-READY\n")
		time.Sleep(10 * time.Minute) // hold until the parent's SIGINT ends the process
	}
	err := runVerifyAudit(nil, nil)
	t.Fatalf("runVerifyAudit returned (%v) instead of being interrupted", err)
}

func copyDirs(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "keyorix-audit-verify-") {
			names = append(names, e.Name())
		}
	}
	return names
}
