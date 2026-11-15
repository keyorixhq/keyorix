package docsdrift

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// PILOT-CLI-TAILS-NOV-1 item 4 (#4281): docs/install/offline-install.sh
//   (a) printed `KEYORIX_RECOVERY_KEY_DONE=1 $0 finish ...` with $0 as typed, which is
//       relative and wrong after the script has cd'd into --dir, and without the `sh`
//       an operator needs when the file is not executable;
//   (b) stop_server removed server.pid and said "server stopped" even when kill failed.

func offlineInstallScript(t *testing.T) (sh, script string) {
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

// The printed "run it again" commands carry the script's absolute path, even when the
// script was started by a relative path from another directory.
func TestOfflineInstallFinishPrintsAnAbsoluteScriptPath(t *testing.T) {
	sh, script := offlineInstallScript(t)
	root := repoRoot(t)
	dir := filepath.Join(t.TempDir(), "kx")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	rel := filepath.Join("docs", "install", "offline-install.sh")
	cmd := exec.Command(sh, rel, "finish", "--dir", dir)
	cmd.Dir = root // so $0 is the relative path docs/install/offline-install.sh
	cmd.Env = filteredEnv("KEYORIX_RECOVERY_KEY_DONE")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("finish (no recovery key yet) should stop with the operator step and exit 0: %v\n%s", err, out)
	}
	want := "KEYORIX_RECOVERY_KEY_DONE=1 sh " + script + " finish --dir " + dir
	if !strings.Contains(string(out), want) {
		t.Fatalf("output does not contain %q:\n%s", want, out)
	}
	if strings.Contains(string(out), "KEYORIX_RECOVERY_KEY_DONE=1 "+rel) {
		t.Fatalf("the relative script path is still printed:\n%s", out)
	}
}

func filteredEnv(drop string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, drop+"=") {
			env = append(env, kv)
		}
	}
	return env
}

// stopServerHarness runs the script's own stop_server function (cut out of the script, so
// the test cannot drift from it) in a directory holding server.pid. kill is a shell
// builtin, so a PATH stub cannot replace it; the harness defines a `kill` function that
// refuses to deliver a signal (as for a process owned by another user) but keeps `kill -0`
// honest, so liveness is still real.
func stopServerHarness(t *testing.T, script, dir string, killWorks bool) *exec.Cmd {
	t.Helper()
	body, err := exec.Command("sed", "-n", "/^stop_server() {/,/^}/p", script).Output()
	if err != nil || !strings.Contains(string(body), "stop_server()") {
		t.Fatalf("cannot cut stop_server out of %s: %v", script, err)
	}
	harness := "set -eu\n" +
		"die() { echo \"offline-install: $*\" >&2; exit 1; }\n"
	if !killWorks {
		harness += "kill() { if [ \"$1\" = -0 ]; then command kill -0 \"$2\"; else return 1; fi; }\n"
	}
	harness += string(body) + "\ncd \"$1\"\nstop_server\n"
	sh, _ := exec.LookPath("sh")
	return exec.Command(sh, "-c", harness, "harness", dir)
}

func startSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	p := exec.Command("sleep", "120")
	if err := p.Start(); err != nil {
		t.Skipf("cannot start a helper process: %v", err)
	}
	// Exactly one goroutine calls Wait (concurrent Wait calls on one exec.Cmd race). It also
	// reaps the process, so `kill -0` in the script sees it gone once it has been stopped.
	done := make(chan struct{})
	go func() { _ = p.Wait(); close(done) }()
	t.Cleanup(func() { _ = p.Process.Kill(); <-done })
	return p
}

func TestOfflineInstallStopServer(t *testing.T) {
	_, script := offlineInstallScript(t)

	writePid := func(t *testing.T, pid int) (dir, pidFile string) {
		dir = t.TempDir()
		pidFile = filepath.Join(dir, "server.pid")
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, pidFile
	}

	t.Run("kill fails and the process is alive: dies, keeps server.pid", func(t *testing.T) {
		p := startSleeper(t)
		dir, pidFile := writePid(t, p.Process.Pid)
		out, err := stopServerHarness(t, script, dir, false).CombinedOutput()
		if err == nil {
			t.Fatalf("stop_server succeeded although it could not stop the server:\n%s", out)
		}
		want := fmt.Sprintf("could not stop server (pid %d)", p.Process.Pid)
		if !strings.Contains(string(out), want) {
			t.Fatalf("output does not say %q:\n%s", want, out)
		}
		if strings.Contains(string(out), "server stopped") {
			t.Fatalf("it claims the server stopped:\n%s", out)
		}
		if _, err := os.Stat(pidFile); err != nil {
			t.Fatalf("server.pid was removed although the server is still running: %v", err)
		}
	})

	t.Run("kill works: stops the process, removes server.pid", func(t *testing.T) {
		p := startSleeper(t)
		dir, pidFile := writePid(t, p.Process.Pid)
		out, err := stopServerHarness(t, script, dir, true).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "server stopped") {
			t.Fatalf("stop_server: %v\n%s", err, out)
		}
		if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
			t.Fatalf("server.pid should be gone: %v", err)
		}
	})

	t.Run("stale pid file (process already gone): clears it", func(t *testing.T) {
		p := exec.Command("true")
		if err := p.Run(); err != nil {
			t.Skipf("cannot run a helper process: %v", err)
		}
		dir, pidFile := writePid(t, p.Process.Pid)
		out, err := stopServerHarness(t, script, dir, false).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "server stopped") {
			t.Fatalf("a stale pid is not an error: %v\n%s", err, out)
		}
		if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
			t.Fatalf("stale server.pid should be removed: %v", err)
		}
	})
}
