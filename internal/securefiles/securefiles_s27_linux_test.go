//go:build linux

package securefiles

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSecureWriteFileSync_S27_SyncError_FIFO exercises the f.Sync() error branch in
// SecureWriteFileSync (lines 157-160). On Linux, fsync(2) on a named pipe (FIFO)
// returns EINVAL because pipes are not backed by a block device and have no persistent
// data to flush. The test therefore creates a FIFO inside the base directory and calls
// SecureWriteFileSync against it:
//
//   - Open(O_WRONLY|O_CREATE|O_TRUNC|O_NOFOLLOW) on an existing FIFO succeeds
//     (O_TRUNC is a no-op on pipes; O_NOFOLLOW is satisfied — a FIFO is not a symlink;
//     O_CREATE does nothing since the file already exists).
//   - fchmod(fd, perm) succeeds because the FIFO is owned by the current process.
//   - Write(data) succeeds because the goroutine below drains the read end.
//   - fsync(fd) returns EINVAL, triggering the error return at lines 157-160.
func TestSecureWriteFileSync_S27_SyncError_FIFO(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root-owned fds may behave differently; skipping to keep test predictable")
	}

	base := t.TempDir()
	fifoName := "sync-error-pipe"
	fifoPath := base + "/" + fifoName

	// Create the FIFO before calling SecureWriteFileSync (mkfifo, not os.Create).
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		t.Skipf("mkfifo failed (%v) — cannot set up FIFO for this test", err)
	}

	// Goroutine drains the read end so the Write in SecureWriteFileSync doesn't block.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		r, err := os.OpenFile(fifoPath, os.O_RDONLY, 0)
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n == 0 || rerr != nil {
				_ = r.Close()
				return
			}
		}
	}()
	defer func() { <-readerDone }()

	// SecureWriteFileSync opens the FIFO for writing, succeeds on Open+Chmod+Write,
	// then hits EINVAL from fsync — covering lines 157-160.
	err := SecureWriteFileSync(base, fifoName, []byte("key-material"), 0600)
	require.Error(t, err, "SecureWriteFileSync must fail when fsync returns EINVAL on a pipe")
}
