//go:build linux

package integrity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// On Linux fs-verity is checked before the manifest, so a FIFO at the running
// binary's path must not block in the platform fs-verity open either.
func TestFIFOExecutableDoesNotHangFSVerity(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "keyorix-server")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	env := linuxEnv(root)
	env.Executable = func() (string, error) { return fifo, nil }
	env.FSVerity = platformFSVerity{}
	l := lineOf(collectWithin(t, env, fifo), CheckFSVerity)
	if l.State != StateUnknown {
		t.Fatalf("a FIFO executable must give unknown fs-verity, got %s", l)
	}
	if _, err := os.Stat(fifo); err != nil {
		t.Fatal(err)
	}
}
