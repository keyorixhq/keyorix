package serverguard

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// REVIEW-SERVERGUARD-RECOVERYKEY-1 F4, the acquire-time half: openLockFile and
// flock are two calls. If the sidecar is unlinked (or replaced) between them,
// the flock lands on a file the path no longer names, and the caller holds a
// lock nobody else can meet. The acquisition must check that the path still
// names the locked file, and try again (or fail) when it does not.

// onceAfterLockFileOpen runs fn the first time a lock file has been opened and
// not yet locked, then removes itself, so fn may call the package itself.
func onceAfterLockFileOpen(t *testing.T, fn func(path string)) {
	t.Helper()
	t.Cleanup(func() { afterLockFileOpen = nil })
	afterLockFileOpen = func(path string) {
		afterLockFileOpen = nil
		fn(path)
	}
}

// TestSQLitePresence_SidecarUnlinkedBeforeFlock_AdminWins: the server opens the
// sidecar, an operator deletes it, an admin command creates a new one and takes
// it exclusively, and only then does the server's flock run, on the deleted
// file. The server must be refused, not start beside the admin command.
func TestSQLitePresence_SidecarUnlinkedBeforeFlock_AdminWins(t *testing.T) {
	cfg, lockPath := sqliteGuardCfg(t)
	var admin *Exclusive
	onceAfterLockFileOpen(t, func(string) {
		if err := os.Remove(lockPath); err != nil {
			t.Fatal(err)
		}
		x, err := AcquireExclusive(cfg)
		if err != nil {
			t.Fatalf("precondition: the admin command takes the new sidecar: %v", err)
		}
		admin = x
	})
	p, err := AcquirePresence(cfg)
	defer func() { _ = admin.Release() }()
	if err == nil {
		_ = p.Release()
		t.Fatal("a server started beside an admin command: its flock landed on the deleted sidecar")
	}
	if !strings.Contains(err.Error(), "an admin operation is running") {
		t.Fatalf("want the admin-running refusal, got %v", err)
	}
}

// TestSQLiteExclusive_SidecarUnlinkedBeforeFlock_ServerWins: the mirror image.
// The admin command's exclusive flock must not land on a deleted file while a
// server holds the new one shared.
func TestSQLiteExclusive_SidecarUnlinkedBeforeFlock_ServerWins(t *testing.T) {
	cfg, lockPath := sqliteGuardCfg(t)
	var server *Presence
	onceAfterLockFileOpen(t, func(string) {
		if err := os.Remove(lockPath); err != nil {
			t.Fatal(err)
		}
		p, err := AcquirePresence(cfg)
		if err != nil {
			t.Fatalf("precondition: the server takes the new sidecar: %v", err)
		}
		server = p
	})
	x, err := AcquireExclusive(cfg)
	defer func() { _ = server.Release() }()
	if err == nil {
		_ = x.Release()
		t.Fatal("an admin command got the exclusive lock beside a server: its flock landed on the deleted sidecar")
	}
	if !IsLockHeld(err) {
		t.Fatalf("want a lock-held refusal, got %v", err)
	}
}

// TestSQLiteAcquire_SidecarUnlinkedBeforeFlock_NobodyElse_Retries: with no
// competitor, a sidecar deleted between open and flock is simply opened again:
// the acquisition succeeds and the lock it holds is the one the path names
// (an admin command afterwards is refused).
func TestSQLiteAcquire_SidecarUnlinkedBeforeFlock_NobodyElse_Retries(t *testing.T) {
	cfg, lockPath := sqliteGuardCfg(t)
	onceAfterLockFileOpen(t, func(string) {
		if err := os.Remove(lockPath); err != nil {
			t.Fatal(err)
		}
	})
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence after a one-off unlink: %v", err)
	}
	defer func() { _ = p.Release() }()
	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		t.Fatal("the server's lock is not on the file the path names: an admin command got the exclusive lock beside it")
	}
}

// TestSQLiteAcquire_SidecarReplacedOnEveryTry_FailsLoud: a path that never
// names the file just locked (a process replacing it in a loop, or a filesystem
// whose inode numbers are not stable) ends in a clear error after a few tries,
// never in a lock on the wrong file.
func TestSQLiteAcquire_SidecarReplacedOnEveryTry_FailsLoud(t *testing.T) {
	cfg, lockPath := sqliteGuardCfg(t)
	t.Cleanup(func() { afterLockFileOpen = nil })
	afterLockFileOpen = func(string) {
		if err := os.Remove(lockPath); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if p, err := AcquirePresence(cfg); err == nil {
		_ = p.Release()
		t.Fatal("AcquirePresence succeeded although the path never named the locked file")
	} else if !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("want an error saying the lock file kept being replaced, got %v", err)
	}
	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		t.Fatal("AcquireExclusive succeeded although the path never named the locked file")
	} else if IsLockHeld(err) || !strings.Contains(err.Error(), "was replaced") {
		t.Fatalf("want a non-lock-held error saying the lock file kept being replaced, got %v", err)
	}
}

// TestSQLiteAcquire_FlockUnsupported_FailsLoud: on a filesystem without flock
// support (some network and FUSE mounts return ENOTSUP, ENOLCK or EINVAL) both
// sides fail at start with a message naming the filesystem, not with the
// "an admin operation is running" refusal (which would send the operator
// looking for a process that does not exist), and the admin side is not
// reported as lock-held (so --force cannot mistake it for a server).
func TestSQLiteAcquire_FlockUnsupported_FailsLoud(t *testing.T) {
	cfg, _ := sqliteGuardCfg(t)
	for _, errno := range []syscall.Errno{syscall.ENOTSUP, syscall.ENOLCK, syscall.EINVAL} {
		flockFn = func(int, int) error { return errno }
		_, perr := AcquirePresence(cfg)
		_, xerr := AcquireExclusive(cfg)
		flockFn = syscall.Flock
		for side, err := range map[string]error{"AcquirePresence": perr, "AcquireExclusive": xerr} {
			switch {
			case err == nil:
				t.Errorf("%v: %s succeeded without a lock", errno, side)
			case IsLockHeld(err) || strings.Contains(err.Error(), "an admin operation is running"):
				t.Errorf("%v: %s reported a lock holder: %v", errno, side, err)
			case !strings.Contains(err.Error(), "does not support file locks"):
				t.Errorf("%v: %s: want a message naming the filesystem's missing lock support, got %v", errno, side, err)
			}
		}
	}
}

// TestSQLiteAcquire_NoInodeNumbers_FailsLoud: the watcher and the acquire-time
// check compare inode numbers. A filesystem that reports none (0) cannot be
// watched, so both sides refuse at start instead of running unwatched.
func TestSQLiteAcquire_NoInodeNumbers_FailsLoud(t *testing.T) {
	cfg, _ := sqliteGuardCfg(t)
	t.Cleanup(func() { lockFileInode = inodeOf })
	lockFileInode = func(os.FileInfo) (uint64, bool) { return 0, false }
	if p, err := AcquirePresence(cfg); err == nil {
		_ = p.Release()
		t.Fatal("AcquirePresence succeeded on a filesystem without inode numbers")
	} else if !strings.Contains(err.Error(), "inode") {
		t.Fatalf("want a message about inode numbers, got %v", err)
	}
	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		t.Fatal("AcquireExclusive succeeded on a filesystem without inode numbers")
	} else if IsLockHeld(err) || !strings.Contains(err.Error(), "inode") {
		t.Fatalf("want a non-lock-held message about inode numbers, got %v", err)
	}
}
