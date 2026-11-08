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

func TestRunChild_RecordsChangeWindow(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	w := &crashWorld{t: t, bin: fakeServerBin(t, "sleep 0.2\necho a > "+marker+"\nsleep 0.2\necho bb > "+marker)}
	var win changeWindow
	_, changes, _, _, err := runChild(w, dir, "unused", []string{"noop"}, &killPlan{kind: "calibrate", window: &win})
	if err != nil {
		t.Fatalf("runChild: %v", err)
	}
	// Each `>` is a truncate and then a write, which the poller may see apart.
	if changes < 2 || win.n != changes {
		t.Fatalf("changes=%d window.n=%d, want at least 2 and equal", changes, win.n)
	}
	if win.first < 150*time.Millisecond || win.last-win.first < 150*time.Millisecond {
		t.Fatalf("window first=%s last=%s does not span the two sleeps", win.first, win.last)
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
