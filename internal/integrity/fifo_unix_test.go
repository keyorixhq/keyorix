//go:build unix

package integrity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// collectWithin runs Collect and fails the test if it does not return in time.
// A plain open(2) of a FIFO blocks until a writer appears, so a hang here is the
// bug. Cleanup opens the FIFO read-write to release a stuck goroutine.
func collectWithin(t *testing.T, env Env, fifo string) Report {
	t.Helper()
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	done := make(chan Report, 1)
	go func() { done <- Collect(env) }()
	select {
	case r := <-done:
		return r
	case <-time.After(5 * time.Second):
		t.Fatalf("Collect blocked on the FIFO %s", fifo)
		return Report{}
	}
}

// A FIFO named checksums.txt next to the binary must not hang the posture check.
func TestFIFOManifestDoesNotHang(t *testing.T) {
	env := manifestEnv(t, "checksums.txt.sig", "sig")
	exe, _ := env.Executable()
	fifo := filepath.Join(filepath.Dir(exe), manifestName)
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	l := lineOf(collectWithin(t, env, fifo), CheckManifest)
	if l.State != StateUnknown {
		t.Fatalf("a FIFO manifest must be unknown, got %s", l)
	}
}

// A FIFO named comm under an injected proc root must be skipped, not waited on.
func TestFIFOProcCommDoesNotHang(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "proc", "123", "comm")
	if err := os.MkdirAll(filepath.Dir(fifo), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	type res struct {
		on  bool
		err error
	}
	done := make(chan res, 1)
	go func() {
		on, err := keylimeInProc(root)
		done <- res{on, err}
	}()
	select {
	case r := <-done:
		if r.on || r.err != nil {
			t.Fatalf("a FIFO comm must be skipped: on=%v err=%v", r.on, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("keylimeInProc blocked on the FIFO %s", fifo)
	}
}

// The same holds for the /sys and /proc style reads under the injectable root.
func TestFIFOUnderRootDoesNotHang(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, filepath.FromSlash("sys/kernel/security/lockdown"))
	if err := os.MkdirAll(filepath.Dir(fifo), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	l := lineOf(collectWithin(t, linuxEnv(root), fifo), CheckLockdown)
	if l.State != StateUnknown {
		t.Fatalf("a FIFO lockdown file must be unknown, got %s", l)
	}
}
