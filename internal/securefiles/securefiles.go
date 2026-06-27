package securefiles

import (
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
// that the resolved path remains inside baseDir.
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

// FixFilePerms verifies file permissions and ownership.
// If autofix=true, it will attempt to correct any mismatches.
func FixFilePerms(files []FilePermSpec, autofix bool) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("cannot get current user: %w", err)
	}
	currentUID, _ := strconv.Atoi(currentUser.Uid)

	hasWarnings := false // a mismatch was found (fixed or not)
	unresolved := false  // a problem REMAINS — stat/chmod/chown failed, so autofix didn't help

	for _, f := range files {
		// Lstat (not Stat) so a symlink is detected rather than dereferenced: os.Chmod /
		// os.Chown FOLLOW symlinks, so a symlink planted in the key directory would
		// otherwise redirect the perm/owner fix to an arbitrary target (an arbitrary chown
		// when running as root). Refuse to "fix" a symlinked path.
		info, err := os.Lstat(f.Path)
		if err != nil {
			fmt.Printf("[WARN] Cannot stat file %s: %v\n", f.Path, err)
			hasWarnings = true
			unresolved = true
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			fmt.Printf("[WARN] Refusing to fix %s: it is a symlink (won't follow it to an arbitrary target)\n", f.Path)
			hasWarnings = true
			unresolved = true
			continue
		}

		// Check permissions
		actualMode := info.Mode().Perm()
		if actualMode != f.Mode {
			msg := fmt.Sprintf("File %s has mode %o but expected %o", f.Path, actualMode, f.Mode)
			hasWarnings = true
			if autofix {
				if err := os.Chmod(f.Path, f.Mode); err != nil {
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
			continue
		}

		fileUID := int(stat.Uid)
		if fileUID != currentUID {
			msg := fmt.Sprintf("File %s is owned by uid %d, expected uid %d", f.Path, fileUID, currentUID)
			hasWarnings = true
			if autofix {
				if err := os.Chown(f.Path, currentUID, int(stat.Gid)); err != nil {
					fmt.Printf("[ERROR] Failed to chown %s: %v\n", f.Path, err)
					unresolved = true
				} else {
					fmt.Printf("[FIXED] %s\n", msg)
				}
			} else {
				fmt.Printf("[WARN] %s\n", msg)
			}
		}
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
