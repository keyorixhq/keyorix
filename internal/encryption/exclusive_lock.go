// exclusive_lock.go — single-live-DEK-holder coordination (ADR-010 / #92/#196).
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
//
// #196: that exclusive lock alone leaves every OTHER short-lived, local key-
// management CLI command (status/validate/fix-perms/upgrade-aad/init) with no
// coordination at all — none of them acquire anything today, so one can read (or,
// for upgrade-aad, write under) the DEK while a rotation sweep or a live server is
// concurrently replacing it. Since these commands don't themselves rotate the
// DEK, they don't need to exclude EACH OTHER — only the actual writer (server or
// rotation/migrate-provider). acquireSharedKeyLock takes the same lock file in
// flock's SHARED mode: any number of shared holders can coexist, but flock
// refuses a shared request while another process holds the file exclusively
// (and vice versa), so this still refuses to run while a live server or an
// in-progress rotation/migrate-provider holds the lock.
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

// acquireSharedKeyLock takes a non-blocking SHARED advisory lock on the SAME
// dek.lock file acquireExclusiveKeyLock uses (#196). Any number of processes can
// hold the shared lock at once — concurrent local CLI commands never contend
// with each other over it — but a shared request is refused outright while
// another process holds the file EXCLUSIVELY, which is exactly what a live
// server (from startup) or an in-progress rotation/migrate-provider (for the
// duration of its write) does. That refusal is the whole point: it stops a
// local, non-rotating CLI command from reading (or writing under) a DEK that's
// concurrently being replaced.
func acquireSharedKeyLock(baseDir string) (*os.File, error) {
	path := filepath.Join(baseDir, serverLockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- operator-configured key directory, not user input
	if err != nil {
		return nil, fmt.Errorf("open DEK lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another process holds the DEK lock exclusively (a live server, or an in-progress rotation/migrate-provider): %w", err)
	}
	return f, nil
}

// releaseKeyLock releases a lock taken by acquireExclusiveKeyLock or
// acquireSharedKeyLock — flock's LOCK_UN releases whichever mode is held on the
// fd, so one release path serves both. Nil is a safe no-op (nothing was held).
func releaseKeyLock(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}
