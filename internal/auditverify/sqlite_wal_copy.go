package auditverify

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// SQLite reads a WAL-mode file (header read-version byte 19 == 2, which every
// keyorix database has: storage/factory_local.go sets journal_mode=WAL) only
// through a -shm wal-index it creates beside the file, even on a mode=ro
// connection. Opened in place, an evidence copy therefore gained -wal/-shm in
// its directory, and on a read-only directory (an evidence share, chmod 0500)
// the open failed with SQLITE_READONLY_CANTINIT (1544) (#4350). immutable=1
// is not the fix: it ignores an un-checkpointed -wal shipped with the copy,
// so rows would silently drop out of the verifier's view.
//
// Instead such a file is verified from a private copy: the database and its
// -wal (if any) go into a fresh 0700 directory from os.MkdirTemp, SQLite's
// sidecars are created there, and the directory is removed when the DB is
// closed (or at once if opening fails). The artifact's directory is only read.
// The copy is the whole vault database (ciphertext, hashes, PII, the audit
// trail), so only OpenSQLiteReadOnly (an operator-named artifact) makes one;
// a server-owned file is opened in place (OpenSQLiteReadOnlyInPlace). A
// process killed without Close or RemovePrivateCopy (SIGKILL, a crash) leaves
// the keyorix-audit-verify-* directory behind.

// sqliteCopyName is the copy's file name inside the private directory: fixed,
// so no byte of the operator's file name reaches SQLite's URI parser.
const sqliteCopyName = "audit.db"

// sqliteNeedsPrivateCopy reports whether opening path in place would create
// SQLite sidecars beside it: the header says WAL (byte 18 or 19 == 2) or a
// -wal is already there. A file that already has both a -wal and a -shm in a
// writable directory is in use by (or was left by) a SQLite process: opening
// it adds no entry and never writes the main file, and a copy taken while its
// owner commits and checkpoints could be torn, so it is read in place, as
// every other SQLite reader of that file does. Anything but a regular file
// (a FIFO, a device) is left to SQLite as before: reading its header could
// block.
func sqliteNeedsPrivateCopy(path string) bool {
	if !regularFileExists(path) {
		return false // SQLite reports a missing or odd file itself
	}
	walHeader := false
	if f, err := os.Open(path); err == nil { // #nosec G304 -- the operator-named artifact
		var hdr [20]byte
		if n, _ := io.ReadFull(f, hdr[:]); n == len(hdr) {
			walHeader = hdr[18] == 2 || hdr[19] == 2
		}
		_ = f.Close()
	}
	walExists := regularFileExists(path + "-wal")
	if !walHeader && !walExists {
		return false
	}
	if walExists && regularFileExists(path+"-shm") && unix.Access(filepath.Dir(path), unix.W_OK) == nil &&
		unix.Access(path+"-shm", unix.R_OK|unix.W_OK) == nil {
		return false
	}
	return true
}

func regularFileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// copySQLiteToPrivateDir copies path (and path-wal, if present) into a new
// 0700 directory and returns the copy's path and a func that removes the
// directory. On error nothing is left behind.
func copySQLiteToPrivateDir(path string) (copyPath string, cleanup func(), err error) {
	need, err := fileSize(path)
	if err != nil {
		return "", nil, err
	}
	walPath := path + "-wal"
	// A -wal that is there but not a regular file (a directory, a FIFO, a
	// symlink) is refused: copying the main file alone would silently drop
	// that -wal's frames from the verifier's view.
	if fi, err := os.Lstat(walPath); err == nil && !fi.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%s is not a regular file (%s): verify a copy whose -wal is a plain file, "+
			"or check the database in place with the server's own tools", walPath, fi.Mode().Type())
	}
	hasWAL := regularFileExists(walPath)
	if hasWAL {
		w, err := fileSize(walPath)
		if err != nil {
			return "", nil, err
		}
		need = saturatingAdd(need, w)
	}

	dir, err := os.MkdirTemp("", "keyorix-audit-verify-")
	if err != nil {
		return "", nil, fmt.Errorf("this is a WAL-mode SQLite file, which is verified from a private copy, "+
			"but no temporary directory could be created (%w): set TMPDIR to a writable directory", err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs the owner x bit; 0700 is the strictest usable mode
		cleanup()
		return "", nil, fmt.Errorf("restrict temporary copy directory %s: %w", dir, err)
	}
	if avail, ok := availableBytes(dir); ok && avail < need {
		cleanup()
		return "", nil, fmt.Errorf("this is a WAL-mode SQLite file, which is verified from a private copy: "+
			"the copy needs %d bytes (the database and its -wal) but only %d are free in %s; "+
			"set TMPDIR to a directory with at least that much free space", need, avail, filepath.Dir(dir))
	}

	copyPath = filepath.Join(dir, sqliteCopyName)
	if err := copyFileExclusive(path, copyPath); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("copy WAL-mode SQLite file to %s for verification: %w", dir, err)
	}
	if hasWAL {
		if err := copyFileExclusive(walPath, copyPath+"-wal"); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("copy %s to %s for verification: %w", walPath, dir, err)
		}
	}
	return copyPath, cleanup, nil
}

func fileSize(p string) (int64, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", p, err)
	}
	return fi.Size(), nil
}

func saturatingAdd(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// availableBytes is the space free to this (non-root) process on dir's
// filesystem; ok is false when it cannot be determined, in which case the
// copy itself reports a shortfall.
func availableBytes(dir string) (int64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, false
	}
	bsize := int64(st.Bsize) // #nosec G115 -- a block size
	if bsize <= 0 {
		return 0, false
	}
	if st.Bavail > uint64(math.MaxInt64/bsize) { // #nosec G115 -- bsize > 0 is checked above, so the quotient is positive
		return math.MaxInt64, true
	}
	return int64(st.Bavail) * bsize, true // #nosec G115 -- bounded above
}

func copyFileExclusive(src, dst string) (err error) {
	in, err := os.Open(src) // #nosec G304 -- the operator-named artifact
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- inside our own MkdirTemp dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		if errors.Is(err, unix.ENOSPC) {
			return fmt.Errorf("%w: set TMPDIR to a directory with more free space", err)
		}
		return err
	}
	return out.Close()
}
