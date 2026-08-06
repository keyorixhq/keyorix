package securefiles

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var FilePermsCmd = &cobra.Command{
	Use:   "fileperms",
	Short: "Manage critical file permissions",
}

// FilePermSpec describes a file and its required permissions and ownership
type FilePermSpec struct {
	Path string
	Mode os.FileMode // e.g., 0600
}

// isPathInsideBase ensures that targetPath is inside baseDir. It resolves symlinks on
// both sides before comparing, so a symlink planted inside baseDir cannot redirect the
// read/write to a location outside it (a purely lexical filepath.Clean check would miss
// that). The target file itself may not exist yet (writes), so its longest existing
// ancestor is resolved and the unresolved tail re-attached.
func isPathInsideBase(baseDir, targetPath string) (bool, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false, err
	}
	if resolved, rerr := filepath.EvalSymlinks(absBase); rerr == nil {
		absBase = resolved
	} else if !os.IsNotExist(rerr) {
		return false, rerr
	}

	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false, err
	}
	absTarget = resolveExistingAncestor(absTarget)

	baseWithSlash := absBase + string(os.PathSeparator)
	return absTarget == absBase || strings.HasPrefix(absTarget, baseWithSlash), nil
}

// resolveExistingAncestor returns p with its longest existing prefix run through
// filepath.EvalSymlinks (collapsing any symlink in the real path) and the remaining
// non-existent suffix re-appended unchanged. This lets the containment check resolve
// symlinks even when the final target does not exist yet.
func resolveExistingAncestor(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	dir, file := filepath.Split(p)
	dir = filepath.Clean(dir)
	if dir == p { // reached the filesystem root; nothing left to resolve
		return p
	}
	return filepath.Join(resolveExistingAncestor(dir), file)
}

// SafeReadFile reads a file at filepath.Join(baseDir, filePath), validating
// that the resolved path remains inside baseDir.
func SafeReadFile(baseDir, filePath string) ([]byte, error) {
	fullPath := filepath.Join(baseDir, filePath)
	cleanPath := filepath.Clean(fullPath)

	ok, err := isPathInsideBase(baseDir, cleanPath)
	if err != nil {
		return nil, fmt.Errorf("path validation error: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("access denied: file %q is outside of %q", cleanPath, baseDir)
	}

	return os.ReadFile(cleanPath)
}

// resolveInside joins and cleans baseDir/path and verifies the result stays
// inside baseDir, returning the validated absolute-ish clean path.
func resolveInside(baseDir, path string) (string, error) {
	cleanPath := filepath.Clean(filepath.Join(baseDir, path))
	ok, err := isPathInsideBase(baseDir, cleanPath)
	if err != nil {
		return "", fmt.Errorf("path validation error: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("access denied: file %q is outside of %q", cleanPath, baseDir)
	}
	return cleanPath, nil
}

// SecureWriteFile writes data to filepath.Join(baseDir, path), validating
// that the resolved path remains inside baseDir. The file mode is enforced
// even if the file pre-existed with a looser mode (O_CREATE|O_TRUNC alone
// only applies perm at creation time and leaves an existing file's mode
// untouched, so this Chmods explicitly after open — mirroring
// SecureWriteFileSync, minus the fsync). Callers writing durability-critical
// key material should prefer SecureWriteFileSync instead.
func SecureWriteFile(baseDir, path string, data []byte, perm os.FileMode) error {
	cleanPath, err := resolveInside(baseDir, path)
	if err != nil {
		return err
	}
	// O_NOFOLLOW refuses to write THROUGH a final-component symlink. The containment
	// check resolves EXISTING symlinks, but a DANGLING final symlink (its target not yet
	// existing) slips past it — os.WriteFile would then follow it and create a file
	// outside baseDir. With O_NOFOLLOW the open fails (ELOOP) instead of following it.
	f, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm) // #nosec G304 -- cleanPath validated inside baseDir by resolveInside
	if err != nil {
		return err
	}
	// O_TRUNC keeps a pre-existing file's mode; force the intended perms.
	if cerr := f.Chmod(perm); cerr != nil {
		_ = f.Close()
		return cerr
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	return f.Close()
}

// SecureWriteFileSync writes data like SecureWriteFile but fsyncs the file before
// returning, so the bytes are durable on disk rather than merely in the page
// cache. Use it for key material (DEK/KEK/salt) whose loss is unrecoverable: a
// non-durable write can be lost on power failure even after the call returns,
// which — combined with overwriting the previous key — risks orphaning all
// ciphertext. Pair it with SyncDir after any rename to make the rename durable
// too. The file mode is enforced even if the file pre-existed with a looser mode.
func SecureWriteFileSync(baseDir, path string, data []byte, perm os.FileMode) error {
	cleanPath, err := resolveInside(baseDir, path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm) // #nosec G304 -- cleanPath validated inside baseDir by resolveInside; O_NOFOLLOW refuses a final-component symlink
	if err != nil {
		return err
	}
	// O_TRUNC keeps a pre-existing file's mode; force the intended perms.
	if cerr := f.Chmod(perm); cerr != nil {
		_ = f.Close()
		return cerr
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return serr
	}
	return f.Close()
}

// SyncDir fsyncs the directory dirPath so a preceding file create or rename
// within it is durable (the directory entry is flushed). On platforms where
// opening a directory for sync is unsupported the error is returned to the
// caller to decide; on Linux/macOS this is the standard create→fsync(file)→
// rename→fsync(dir) durability pattern.
func SyncDir(dirPath string) error {
	d, err := os.Open(dirPath) // #nosec G304 -- caller-controlled key directory, not network input
	if err != nil {
		return err
	}
	if serr := d.Sync(); serr != nil {
		_ = d.Close()
		return serr
	}
	return d.Close()
}

// SecureDeleteFile overwrites path with random bytes, then zeros, fsyncing after each
// pass, before unlinking it — a best-effort "shred" for key-material backups that
// should not linger recoverable on disk (e.g. a pre-migration wrapped-DEK backup, whose
// plaintext-after-unwrap is byte-identical to the DEK still in active use). This is NOT
// a guarantee on copy-on-write filesystems, SSDs with wear-leveling, or any snapshotted/
// replicated storage — those may retain the original blocks regardless of what gets
// written to the logical file — but it's strictly better than a plain unlink, and is the
// same caveat any shred(1)-style tool carries.
func SecureDeleteFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	size := info.Size()

	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- caller-controlled key-backup path, not network input
	if err != nil {
		return err
	}
	overwrite := func(pattern func([]byte) error) error {
		buf := make([]byte, size)
		if err := pattern(buf); err != nil {
			return err
		}
		if _, err := f.WriteAt(buf, 0); err != nil {
			return err
		}
		return f.Sync()
	}
	if err := overwrite(func(b []byte) error { _, err := rand.Read(b); return err }); err != nil {
		_ = f.Close()
		return fmt.Errorf("shred pass (random) failed: %w", err)
	}
	if err := overwrite(func(b []byte) error { return nil /* buf is already zero-valued */ }); err != nil {
		_ = f.Close()
		return fmt.Errorf("shred pass (zero) failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// FixFilePerms verifies file permissions and ownership.
// If autofix=true, it will attempt to correct any mismatches.
func FixFilePerms(files []FilePermSpec, autofix bool) error { // NOSONAR -- cognitive complexity 33, suppress go:S3776
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("cannot get current user: %w", err)
	}
	currentUID, _ := strconv.Atoi(currentUser.Uid)

	hasWarnings := false // a mismatch was found (fixed or not)
	unresolved := false  // a problem REMAINS — stat/chmod/chown failed, so autofix didn't help

	for _, f := range files {
		// Open with O_NOFOLLOW so a symlink at the final path component is refused
		// (ELOOP) rather than followed. This replaces a prior Lstat-then-Chmod/Chown-
		// by-path design: Lstat correctly detected a symlink up front, but the
		// subsequent os.Chmod(f.Path, ...) / os.Chown(f.Path, ...) calls re-resolved
		// the path and FOLLOW a final-component symlink, leaving a TOCTOU window
		// between the check and the fix — a symlink swapped in after Lstat (or simply
		// never seen by it, e.g. a race with a concurrent attacker) would redirect the
		// chmod/chown to an arbitrary target (an arbitrary chown when running as
		// root). Operating on the returned *os.File's Chmod/Chown (fd-based, not
		// path-based) closes that window: the fd stays bound to the exact inode
		// opened here, immune to the path being swapped out from under us afterward —
		// mirrors SecureWriteFile/SecureWriteFileSync in this file.
		file, err := os.OpenFile(f.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- caller-controlled key-file list, not network input
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				fmt.Printf("[WARN] Refusing to fix %s: it is a symlink (won't follow it to an arbitrary target)\n", f.Path)
			} else {
				fmt.Printf("[WARN] Cannot open file %s: %v\n", f.Path, err)
			}
			hasWarnings = true
			unresolved = true
			continue
		}

		info, err := file.Stat()
		if err != nil {
			fmt.Printf("[WARN] Cannot stat file %s: %v\n", f.Path, err)
			hasWarnings = true
			unresolved = true
			_ = file.Close()
			continue
		}

		// Check permissions
		actualMode := info.Mode().Perm()
		if actualMode != f.Mode {
			msg := fmt.Sprintf("File %s has mode %o but expected %o", f.Path, actualMode, f.Mode)
			hasWarnings = true
			if autofix {
				if err := file.Chmod(f.Mode); err != nil {
					fmt.Printf("[ERROR] Failed to chmod %s: %v\n", f.Path, err)
					unresolved = true
				} else {
					fmt.Printf("[FIXED] %s\n", msg)
				}
			} else {
				fmt.Printf("[WARN] %s\n", msg)
			}
		}

		// Check ownership
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			fmt.Printf("[WARN] Cannot get stat_t for %s\n", f.Path)
			hasWarnings = true
			unresolved = true
			_ = file.Close()
			continue
		}

		fileUID := int(stat.Uid)
		if fileUID != currentUID {
			msg := fmt.Sprintf("File %s is owned by uid %d, expected uid %d", f.Path, fileUID, currentUID)
			hasWarnings = true
			if autofix {
				if err := file.Chown(currentUID, int(stat.Gid)); err != nil {
					fmt.Printf("[ERROR] Failed to chown %s: %v\n", f.Path, err)
					unresolved = true
				} else {
					fmt.Printf("[FIXED] %s\n", msg)
				}
			} else {
				fmt.Printf("[WARN] %s\n", msg)
			}
		}

		_ = file.Close()
	}

	// Fail closed when a problem remains: either autofix was off and a mismatch exists,
	// or autofix was on but a chmod/chown/stat FAILED (so the insecure state persists).
	// The previous `hasWarnings && !autofix` form silently returned nil when autofix
	// couldn't actually lock a world-readable key file down.
	if unresolved || (hasWarnings && !autofix) {
		return fmt.Errorf("permissions or ownership audit found unresolved issues")
	}

	return nil
}
