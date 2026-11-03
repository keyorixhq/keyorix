package encryption

import (
	"bytes"
	"crypto/fips140"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const fipsSelfTestChildEnv = "ENCRYPTION_FIPS_SELFTEST_CHILD"

// TestRunFIPSSelfTest_PassesUnderFIPS140Only runs the real boot self-test in a
// child process started with GODEBUG=fips140=only: every AEAD and KEK-derived
// key path must pass there, and the posture line must say so. It also runs
// in-process when the whole suite already runs under fips140=only.
func TestRunFIPSSelfTest_PassesUnderFIPS140Only(t *testing.T) {
	if fips140.Enforced() {
		if err := RunFIPSSelfTest(); err != nil {
			t.Fatalf("RunFIPSSelfTest under fips140=only: %v", err)
		}
		line := FIPSSelfTestPostureLine()
		if !strings.HasPrefix(line, "fips140 enforced: yes, self-test passed") {
			t.Fatalf("posture line = %q, want a passed line", line)
		}
		t.Log(line)
		return
	}
	if os.Getenv(fipsSelfTestChildEnv) == "1" {
		t.Fatal("child is not running with fips140=only")
	}
	if testing.Short() {
		t.Skip("spawns a child test process")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunFIPSSelfTest_PassesUnderFIPS140Only$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), fipsSelfTestChildEnv+"=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child under GODEBUG=fips140=only failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("fips140 enforced: yes, self-test passed")) {
		t.Fatalf("child did not report a passed self-test:\n%s", out)
	}
}

// TestRunFIPSSelfTestPaths_EveryPathPassesInThisMode runs each path directly,
// whatever the mode, so a path broken by a code change fails in default CI too,
// not only in a fips140=only job.
func TestRunFIPSSelfTestPaths_EveryPathPassesInThisMode(t *testing.T) {
	for _, p := range fipsSelfTestPaths {
		if err := runFIPSSelfTestPath(p); err != nil {
			t.Errorf("%s: %v", p.name, err)
		}
	}
}

// TestRunFIPSSelfTestPaths_FailingPathIsNamed pins the refusal shape: the first
// failing path, whether it returns an error or panics (the FIPS module's way of
// refusing a non-approved primitive), comes back as a *FIPSSelfTestError naming
// that path, and later paths do not run.
func TestRunFIPSSelfTestPaths_FailingPathIsNamed(t *testing.T) {
	boom := errors.New("refused")
	var laterRan bool
	for _, tc := range []struct {
		name string
		run  func() error
		want string
	}{
		{"error", func() error { return boom }, "refused"},
		{"panic", func() error { panic("crypto/x: use of y is not allowed in FIPS 140-only mode") }, "panic: crypto/x: use of y"},
	} {
		laterRan = false
		paths := []fipsSelfTestPath{
			{"ok path", func() error { return nil }},
			{"fake failing path", tc.run},
			{"later path", func() error { laterRan = true; return nil }},
		}
		err := runFIPSSelfTestPaths(paths)
		var st *FIPSSelfTestError
		if !errors.As(err, &st) {
			t.Fatalf("%s: err = %v, want *FIPSSelfTestError", tc.name, err)
		}
		if st.Path != "fake failing path" {
			t.Errorf("%s: Path = %q, want the failing path", tc.name, st.Path)
		}
		if !strings.Contains(err.Error(), "fake failing path") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not name the path and the cause %q", tc.name, err, tc.want)
		}
		if laterRan {
			t.Errorf("%s: a path after the failing one ran", tc.name)
		}
	}
}

// TestBootFIPSSelfTest_FailingPathRefusesBoot drives the boot hook itself with
// a fake failing path substituted. Under fips140=only it must return the named
// error (server/main.go then refuses to start); outside that mode the paths
// must not run at all (no self-test cost) and the posture line must say the
// self-test was not run.
func TestBootFIPSSelfTest_FailingPathRefusesBoot(t *testing.T) {
	var calls int
	saved := fipsSelfTestPaths
	fipsSelfTestPaths = []fipsSelfTestPath{{"fake failing path", func() error { calls++; return errors.New("refused") }}}
	t.Cleanup(func() {
		fipsSelfTestPaths = saved
		fipsSelfTestMu.Lock()
		fipsSelfTestRan, fipsSelfTestResult = false, nil
		fipsSelfTestMu.Unlock()
	})

	err := BootFIPSSelfTest()
	if !fips140.Enforced() {
		if err != nil || calls != 0 {
			t.Fatalf("not enforced: err = %v, path calls = %d, want nil and 0", err, calls)
		}
		if got, want := FIPSSelfTestPostureLine(), "fips140 enforced: no (self-test not run)"; got != want {
			t.Fatalf("posture line = %q, want %q", got, want)
		}
		return
	}
	var st *FIPSSelfTestError
	if !errors.As(err, &st) || st.Path != "fake failing path" || calls != 1 {
		t.Fatalf("enforced: err = %v, calls = %d, want *FIPSSelfTestError naming the fake path after one call", err, calls)
	}
	if line := FIPSSelfTestPostureLine(); !strings.Contains(line, "self-test FAILED") || !strings.Contains(line, "fake failing path") {
		t.Fatalf("posture line = %q, want a FAILED line naming the path", line)
	}
}
