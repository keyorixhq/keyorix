// exclusive_lock.go — single-live-DEK-holder coordination (ADR-010 / #92).
//
// The DEK rotation CLI is a separate OS process from the running server: without
// coordination, it can promote a new DEK to disk while the server still holds the
// OLD DEK in memory. Writes made after promotion but before the server's next
// restart are sealed under a DEK the server no longer has on disk, and rows the
// sweep re-encrypted become unreadable to the live server until it restarts —
// permanent data loss if that restart never happens. Both the server (for its
// whole lifetime, acquired at startup) and DEK rotation (for the duration of the
// sweep) take an exclusive, non-blocking flock on the same file — whichever runs
// first blocks the other, so rotation simply refuses to run against a live
// server instead of racing it.
package encryption

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// serverLockFileName is the advisory-lock file living alongside dek.key/kek.salt.
const serverLockFileName = "dek.lock"

// acquireExclusiveKeyLock takes a non-blocking exclusive advisory lock on the key
// directory. The returned file must be kept open — closing it (or process exit,
// including a crash) releases the lock automatically, so there is no stale-lock
// cleanup to worry about. Returns an error when another process (a live server,
// or a concurrent rotation) already holds it.
func acquireExclusiveKeyLock(baseDir string) (*os.File, error) {
	path := filepath.Join(baseDir, serverLockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- operator-configured key directory, not user input
	if err != nil {
		return nil, fmt.Errorf("open DEK lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another process already holds the DEK lock (a live server, or a concurrent rotation): %w", err)
	}
	return f, nil
}

// releaseExclusiveKeyLock releases a lock taken by acquireExclusiveKeyLock. Nil is
// a safe no-op (nothing was held).
func releaseExclusiveKeyLock(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}
