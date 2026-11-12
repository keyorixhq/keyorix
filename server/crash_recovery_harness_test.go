//go:build !windows

package main

// crash_recovery_harness_test.go -- unit tests of the fuzz harness itself. They
// run a small shell script in place of keyorix-server, so they need no server
// build and also run with -short.

import (
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeServerBin writes script as an executable that runChild runs in place of
// keyorix-server.
func fakeServerBin(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-server")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatalf("write fake server: %v", err)
	}
	return p
}

// TestRunChild_KilledComesFromWaitStatus pins R6: an iteration counts as killed
// only if SIGKILL actually ended the child. The first case has a child that
// exits by itself while a background process keeps its stdout open, so Wait has
// not returned when the planned kill fires; the signal then reaches nothing.
func TestRunChild_KilledComesFromWaitStatus(t *testing.T) {
	cases := []struct {
		name       string
		script     string
		plan       killPlan
		wantKilled bool
	}{
		{"child already exited", "sleep 1 &\nexit 0", killPlan{kind: "time", after: 200 * time.Millisecond}, false},
		{"child still running", "exec sleep 30", killPlan{kind: "time", after: 100 * time.Millisecond}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := &crashWorld{t: t, bin: fakeServerBin(t, c.script)}
			killed, _, _, out, err := runChild(w, t.TempDir(), "unused", []string{"noop"}, &c.plan)
			if killed != c.wantKilled {
				t.Fatalf("killed=%v, want %v (err=%v, output=%q)", killed, c.wantKilled, err, out)
			}
		})
	}
}

// TestRunChild_DeadlineEndsHungChild pins that a hang comes back as an error the
// fuzz loop can report with its snapshot, instead of a go test timeout.
func TestRunChild_DeadlineEndsHungChild(t *testing.T) {
	w := &crashWorld{t: t, bin: fakeServerBin(t, "exec sleep 30")}
	killed, _, dur, _, err := runChild(w, t.TempDir(), "unused", []string{"noop"}, &killPlan{kind: "calibrate", deadline: 100 * time.Millisecond})
	if !errors.Is(err, errChildDeadline) {
		t.Fatalf("err=%v, want errChildDeadline", err)
	}
	if killed {
		t.Fatal("a deadline stop must not count as a planned kill")
	}
	if dur > 10*time.Second {
		t.Fatalf("hung child took %s to stop", dur)
	}
}

// waitChildReaped blocks until the process whose pid is in pidFile is gone, then
// gives runChild's Wait goroutine a moment to deliver the exit. The pause only
// sharpens the red case: if Wait is slower, the poller just sees the last write
// in its loop instead.
func waitChildReaped(t *testing.T, pidFile string) {
	t.Helper()
	b, err := os.ReadFile(pidFile) //nolint:gosec // test-generated path
	if err != nil {
		t.Errorf("read child pid: %v", err)
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		t.Errorf("child pid %q: %v", b, err)
		return
	}
	for stop := time.Now().Add(20 * time.Second); time.Now().Before(stop); time.Sleep(time.Millisecond) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			time.Sleep(50 * time.Millisecond)
			return
		}
	}
	t.Errorf("child %d still running after its last write", pid)
}

// TestRunChild_RecordsChangeWindow pins that the count and the window include
// every directory change, also one made just before the child exits. Child and
// poller run in lock step, so scheduling cannot change what is sampled: the
// first observed change releases the child and then holds the poller until the
// child has made its last write and exited. Only the sample runChild takes after
// the exit can see that write.
func TestRunChild_RecordsChangeWindow(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	// Outside dir: the handshake files must not count as directory changes.
	ctl := t.TempDir()
	pidFile, release := filepath.Join(ctl, "pid"), filepath.Join(ctl, "release")
	// No sleeps: the child's first write, the release and its last write are
	// ordered by the handshake file alone, so a slow runner cannot reorder them.
	w := &crashWorld{t: t, bin: fakeServerBin(t, "echo $$ > "+pidFile+"\necho a > "+marker+
		"\nuntil [ -e "+release+" ]; do sleep 0.01; done\necho bb > "+marker)}
	var win changeWindow
	released, seenAtRelease := false, 0
	win.onChange = func() {
		if released {
			return
		}
		released = true
		seenAtRelease = win.n
		if err := os.WriteFile(release, nil, 0o600); err != nil {
			t.Errorf("release child: %v", err)
			return
		}
		waitChildReaped(t, pidFile)
	}
	// The deadline only ends a child that was never released.
	_, changes, _, _, err := runChild(w, dir, "unused", []string{"noop"}, &killPlan{kind: "calibrate", deadline: 30 * time.Second, window: &win})
	if err != nil {
		t.Fatalf("runChild: %v", err)
	}
	// Ordering, not wall-clock spans. The poller is held from its first
	// observation until the child has exited, so it sees exactly two states: one
	// before the release and the final one taken after the exit.
	if changes != 2 || win.n != changes {
		t.Fatalf("changes=%d window.n=%d, want exactly 2 and equal", changes, win.n)
	}
	if seenAtRelease != 1 {
		t.Fatalf("%d changes recorded when the child was released, want 1", seenAtRelease)
	}
	if win.first > win.last {
		t.Fatalf("window first=%s is after last=%s", win.first, win.last)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "bb\n" { //nolint:gosec // test-generated path
		t.Fatalf("marker=%q err=%v, want the write made after the release", got, err)
	}
}

func TestDirSig_SeesSameSizeRewrite(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "k")
	if err := os.WriteFile(f, []byte("aaaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := dirSig(dir)
	if err := os.WriteFile(f, []byte("bbbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(f, later, later); err != nil {
		t.Fatal(err)
	}
	if dirSig(dir) == before {
		t.Fatal("same-size rewrite did not change the signature")
	}
}

func TestDrawTimeKill_StaysInChangeWindow(t *testing.T) {
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // test randomness
	win := changeWindow{n: 5, first: 3 * time.Second, last: 4 * time.Second}
	for range 1000 {
		if got := drawTimeKill(rng, win, 10*time.Second); got < win.first || got > win.last {
			t.Fatalf("drew %s outside [%s, %s]", got, win.first, win.last)
		}
	}
	if got := drawTimeKill(rng, changeWindow{}, 10*time.Second); got > 9*time.Second {
		t.Fatalf("fallback drew %s, past 90%% of the calibration", got)
	}
}

// TestUnknownNamesAreRefused pins that a typo cannot silently run nothing.
func TestUnknownNamesAreRefused(t *testing.T) {
	if _, err := parseCrashOps("rotate-dek,no-such-op"); err == nil {
		t.Fatal("unknown KX_CRASH_OPS name accepted")
	}
	got, err := parseCrashOps("rotate-dek,,backup")
	if err != nil || len(got) != 2 || !got["rotate-dek"] || !got["backup"] {
		t.Fatalf("parseCrashOps=%v err=%v", got, err)
	}
	if _, ok := crashOpByName("no-such-op"); ok {
		t.Fatal("crashOpByName found an unknown name")
	}
}

func TestReplayPort_ValidatesTheConfiguredPort(t *testing.T) {
	cases := []struct {
		name, yaml, want string
		wantErr          bool
	}{
		{"valid", "server:\n  http:\n    port: \"18443\"\n", "18443", false},
		{"not numeric", "server:\n  http:\n    port: \"abc\"\n", "", true},
		{"out of range", "server:\n  http:\n    port: \"70000\"\n", "", true},
		{"missing", "server:\n  http:\n    enabled: true\n", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(c.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := replayPort(dir)
			if (err != nil) != c.wantErr || got != c.want {
				t.Fatalf("replayPort=%q err=%v, want %q wantErr=%v", got, err, c.want, c.wantErr)
			}
		})
	}
}
