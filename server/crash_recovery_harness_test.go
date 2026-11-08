//go:build !windows

package main

// crash_recovery_harness_test.go -- unit tests of the fuzz harness itself. They
// run a small shell script in place of keyorix-server, so they need no server
// build and also run with -short.

import (
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
