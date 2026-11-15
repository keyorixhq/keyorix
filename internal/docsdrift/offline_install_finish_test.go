package docsdrift

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// PILOT-INSTALL-SCRIPTS-NOV-1 item 1 (#4281): docs/install/offline-install.sh
// prints a follow-up command that must be runnable as printed, and stop must
// not claim "server stopped" when the server is still running.

func offlineInstallSh(t *testing.T) (sh, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("offline-install.sh is a POSIX shell script")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	return sh, filepath.Join(repoRoot(t), "docs", "install", "offline-install.sh")
}

func TestOfflineInstallFinishLineIsRunnable(t *testing.T) {
	sh, script := offlineInstallSh(t)

	// An install dir with stub binaries and no recovery key: finish must stop,
	// then print the operator step and the line that resumes it.
	home := t.TempDir()
	dir := filepath.Join(home, "kx")
	stubs := t.TempDir()
	for _, d := range []string{filepath.Join(dir, "bin"), filepath.Join(dir, "secrets")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{filepath.Join(dir, "bin", "keyorix-server"), filepath.Join(stubs, "curl")} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "HOME="+home, "PATH="+stubs+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Invoke the script by a RELATIVE path and a RELATIVE --dir, from elsewhere:
	// the printed line must not depend on either.
	cwd := filepath.Dir(dir)
	relScript, err := filepath.Rel(cwd, script)
	if err != nil {
		t.Skipf("no relative path to the script: %v", err)
	}
	cmd := exec.Command(sh, relScript, "finish", "--dir", "kx")
	cmd.Dir = cwd
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("finish: %v\n%s", err, out)
	}

	m := regexp.MustCompile(`(?m)^Then run:\s+(KEYORIX_RECOVERY_KEY_DONE=1 .+)$`).FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("no 'Then run: KEYORIX_RECOVERY_KEY_DONE=1 ...' line in:\n%s", out)
	}
	line := strings.TrimSpace(m[1])
	if strings.Contains(line, "$0") || !strings.Contains(line, " sh /") {
		t.Errorf("finish line should be 'sh <absolute script path> finish --dir <absolute dir>': %q", line)
	}
	wantDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(line, "finish --dir "+wantDir) && !strings.HasSuffix(line, "finish --dir "+dir) {
		t.Errorf("finish line should end with the absolute install dir %q: %q", dir, line)
	}

	// Run it exactly as printed, from the install dir. It must get past the
	// recovery-key step to the posture proof and the server start.
	run := exec.Command("sh", "-c", line)
	run.Dir = dir
	run.Env = env
	out2, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("the printed line %q failed: %v\n%s", line, err, out2)
	}
	if !strings.Contains(string(out2), "12. start the server") {
		t.Errorf("the printed line did not reach the server start:\n%s", out2)
	}
	if pid, err := os.ReadFile(filepath.Join(dir, "server.pid")); err == nil {
		t.Cleanup(func() { _ = exec.Command("kill", strings.TrimSpace(string(pid))).Run() })
	}
}

func TestOfflineInstallStopFailsWhenKillFails(t *testing.T) {
	sh, script := offlineInstallSh(t)

	home := t.TempDir()
	dir := filepath.Join(home, "kx")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	live := exec.Command("sleep", "60")
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })
	pid := strconv.Itoa(live.Process.Pid)
	pidFile := filepath.Join(dir, "server.pid")
	if err := os.WriteFile(pidFile, []byte(pid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// kill is a shell builtin, so a PATH stub cannot replace it: define a
	// function that fails for the TERM and passes `kill -0` (liveness) through,
	// then source the script with its arguments.
	wrapper := `kill() { if [ "$1" = -0 ]; then command kill -0 "$2"; else return 1; fi; }
set -- stop --dir "$KX_DIR"
. "$KX_SCRIPT"`
	cmd := exec.Command(sh, "-c", wrapper)
	cmd.Env = append(os.Environ(), "HOME="+home, "KX_DIR="+dir, "KX_SCRIPT="+script)
	out, err := cmd.CombinedOutput()
	got := string(out)
	if err == nil {
		t.Errorf("stop succeeded although kill failed and pid %s is alive:\n%s", pid, got)
	}
	if !strings.Contains(got, "could not stop server (pid "+pid+")") {
		t.Errorf("missing 'could not stop server (pid %s)':\n%s", pid, got)
	}
	if strings.Contains(got, "server stopped") {
		t.Errorf("printed 'server stopped' for a running server:\n%s", got)
	}
	if _, err := os.Stat(pidFile); err != nil {
		t.Errorf("server.pid was removed although the server is still running: %v", err)
	}
}

func TestOfflineInstallStopClearsStalePid(t *testing.T) {
	sh, script := offlineInstallSh(t)

	home := t.TempDir()
	dir := filepath.Join(home, "kx")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(dir, "server.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(dead.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, script, "stop", "--dir", dir)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "server stopped") {
		t.Errorf("a stale pid should be cleared as stopped: err=%v out=%s", err, out)
	}
	if _, err := os.Stat(pidFile); err == nil {
		t.Error("stale server.pid was not removed")
	}
}
