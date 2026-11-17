package demo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests pin the DEMO-REHEARSAL-2 leftover: native-down.sh swallowed the failure of
// kill -0 / kill, wiped the state dir and reported success while an orphan server still held
// keyorix.db.server.lock; native-up.sh said only "admin init failed". They run the REAL
// scripts against real throwaway processes (no shim for kill), so a server that ignores
// SIGTERM is a real one.

func runNativeDown(t *testing.T, work string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"native-down.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "KEYORIX_DEMO_DIR="+work, "KEYORIX_DEMO_STOP_WAIT=2")
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

// startProc starts `bash -c script` and reaps it in the background (an unreaped child stays
// a zombie, which kill -0 still sees as alive). script must `touch $READY` once it is set up.
func startProc(t *testing.T, script string) int {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	for range 100 {
		if _, err := os.Stat(ready); err == nil {
			return cmd.Process.Pid
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("helper process never became ready")
	return 0
}

func demoWork(t *testing.T, pid string) string {
	t.Helper()
	work := filepath.Join(t.TempDir(), ".demo-native")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "keyorix.db"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pid != "" {
		if err := os.WriteFile(filepath.Join(work, "server.pid"), []byte(pid+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return work
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestNativeDown_StopsARunningServerAndWipes(t *testing.T) {
	pid := startProc(t, `touch "$READY"; exec sleep 60`)
	work := demoWork(t, strconv.Itoa(pid))
	out, code := runNativeDown(t, work, "--wipe")
	if code != 0 || !strings.Contains(out, "stopped server pid "+strconv.Itoa(pid)) {
		t.Fatalf("want exit 0 and 'stopped server pid %d', got %d:\n%s", pid, code, out)
	}
	if exists(work) {
		t.Errorf("--wipe left %s behind", work)
	}
}

func TestNativeDown_StalePidFileIsSaidAndCleared(t *testing.T) {
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	work := demoWork(t, strconv.Itoa(gone.Process.Pid))
	out, code := runNativeDown(t, work)
	if code != 0 || !strings.Contains(out, "was not running (stale pid file removed)") {
		t.Fatalf("want exit 0 and a stale-pid line, got %d:\n%s", code, out)
	}
	if exists(filepath.Join(work, "server.pid")) {
		t.Error("stale server.pid not removed")
	}
	if !exists(filepath.Join(work, "keyorix.db")) {
		t.Error("no --wipe given, but the state dir was touched")
	}
}

func TestNativeDown_ServerThatIgnoresSigtermIsReportedAndNothingIsWiped(t *testing.T) {
	pid := startProc(t, `trap '' TERM; touch "$READY"; while :; do sleep 0.2; done`)
	work := demoWork(t, strconv.Itoa(pid))
	out, code := runNativeDown(t, work, "--wipe")
	if code != 1 {
		t.Fatalf("want exit 1 for a server that could not be stopped, got %d:\n%s", code, out)
	}
	if want := "could not stop server pid " + strconv.Itoa(pid); strings.Count(out, want) != 1 {
		t.Errorf("want exactly one %q line, got:\n%s", want, out)
	}
	if strings.Contains(out, "stopped server pid") || strings.Contains(out, "wiped") {
		t.Errorf("reported success for a server that is still running:\n%s", out)
	}
	if !exists(filepath.Join(work, "keyorix.db")) {
		t.Error("state dir was wiped while the server still runs")
	}
	if !exists(filepath.Join(work, "server.pid")) {
		t.Error("server.pid was removed while the server still runs (a retry would not find it)")
	}
}

func TestNativeDown_UnreadablePidFileFailsInsteadOfWiping(t *testing.T) {
	work := demoWork(t, "not-a-pid")
	out, code := runNativeDown(t, work, "--wipe")
	if code != 1 || !strings.Contains(out, "does not hold a pid") {
		t.Fatalf("want exit 1 and a 'does not hold a pid' line, got %d:\n%s", code, out)
	}
	if !exists(filepath.Join(work, "keyorix.db")) {
		t.Error("state dir was wiped on an unreadable pid file")
	}
}

func TestNativeDown_NothingRunningWipeStillWorks(t *testing.T) {
	work := demoWork(t, "")
	out, code := runNativeDown(t, work, "--wipe")
	if code != 0 || !strings.Contains(out, "wiped") || exists(work) {
		t.Fatalf("want exit 0 and a wiped dir, got %d:\n%s", code, out)
	}
}

func TestNativeUp_AdminInitFailureShowsItsStderr(t *testing.T) {
	e := newNativeEnv(t)
	// Pre-built binaries (native-up.sh builds only what is missing): the server fails the
	// way a real one does, with a reason on stderr and nothing on stdout.
	for name, body := range map[string]string{
		"keyorix-server": "#!/bin/sh\necho 'config: master key file is not writable' >&2\nexit 3\n",
		"keyorix":        "#!/bin/sh\n",
		"totpgen":        "#!/bin/sh\n",
	} {
		p := filepath.Join(e.root, "bin", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	out, code := e.run(t, nil, "--no-helpers")
	if code != 1 {
		t.Fatalf("want exit 1, got %d:\n%s", code, out)
	}
	for _, want := range []string{"admin init failed (exit 3)", "config: master key file is not writable"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
