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

// isPathInsideBase ensures that targetPath is inside baseDir
func isPathInsideBase(baseDir, targetPath string) (bool, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false, err
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false, err
	}

	baseWithSlash := absBase + string(os.PathSeparator)
	return absTarget == absBase || strings.HasPrefix(absTarget, baseWithSlash), nil
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
	return os.WriteFile(cleanPath, data, perm)
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
	f, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
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

	hasWarnings := false

	for _, f := range files {
		info, err := os.Stat(f.Path)
		if err != nil {
			fmt.Printf("[WARN] Cannot stat file %s: %v\n", f.Path, err)
			hasWarnings = true
			continue
		}

		// Check permissions
		actualMode := info.Mode().Perm()
		if actualMode != f.Mode {
			msg := fmt.Sprintf("File %s has mode %o but expected %o", f.Path, actualMode, f.Mode)
			if autofix {
				if err := os.Chmod(f.Path, f.Mode); err != nil {
					fmt.Printf("[ERROR] Failed to chmod %s: %v\n", f.Path, err)
					hasWarnings = true
				} else {
					fmt.Printf("[FIXED] %s\n", msg)
				}
			} else {
				fmt.Printf("[WARN] %s\n", msg)
				hasWarnings = true
			}
		}

		// Check ownership
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			fmt.Printf("[WARN] Cannot get stat_t for %s\n", f.Path)
			hasWarnings = true
			continue
		}

		fileUID := int(stat.Uid)
		if fileUID != currentUID {
			msg := fmt.Sprintf("File %s is owned by uid %d, expected uid %d", f.Path, fileUID, currentUID)
			if autofix {
				if err := os.Chown(f.Path, currentUID, int(stat.Gid)); err != nil {
					fmt.Printf("[ERROR] Failed to chown %s: %v\n", f.Path, err)
					hasWarnings = true
				} else {
					fmt.Printf("[FIXED] %s\n", msg)
				}
			} else {
				fmt.Printf("[WARN] %s\n", msg)
				hasWarnings = true
			}
		}
	}

	if hasWarnings && !autofix {
		return fmt.Errorf("permissions or ownership audit found warnings")
	}

	return nil
}
