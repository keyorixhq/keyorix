// Package securefiles provides symlink-safe file-write primitives for the CLI's local
// file operations: secret export, render --output, scan --report, fix's source-tree
// edits, compliance --output/--csv, and trust keygen. It is ported from the main
// module's internal/securefiles. The cli module cannot import that package directly,
// since cli/go.mod carries no dependency on the main module (ADR-108 Decision A,
// enforced by cli/internal/depguard). It is trimmed to the primitives this module's
// callers need: SecureOpenBeneath and SecureCreateFileHandle here, and CreateFile,
// CreateFileSync and WriteFile in write.go. See the main module's
// internal/securefiles/securefiles.go for the full original and its doc comments on
// the TOCTOU this closes.
package securefiles

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// isPathInsideBase reports whether targetPath resolves inside baseDir, resolving
// symlinks on both sides first. A cheap pre-check only (fails fast on an obviously
// escaping path) -- the actual TOCTOU-safe guarantee comes from SecureOpenBeneath's
// per-component O_NOFOLLOW walk below, not from this string-level check.
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
// filepath.EvalSymlinks and the remaining non-existent suffix re-appended unchanged.
func resolveExistingAncestor(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	dir, file := filepath.Split(p)
	dir = filepath.Clean(dir)
	if dir == p {
		return p
	}
	return filepath.Join(resolveExistingAncestor(dir), file)
}

// resolveInside joins and cleans baseDir/path and verifies the result stays inside
// baseDir. The returned path is for error messages only -- callers must open the file
// via SecureOpenBeneath, never by re-opening this returned string (same TOCTOU reason
// documented on isPathInsideBase).
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

// safeRelComponents cleans relPath and splits it into components, rejecting anything
// absolute, empty, or containing a ".." component. Lexical only -- the containment
// guarantee against symlinks comes from SecureOpenBeneath's walk below.
func safeRelComponents(relPath string) ([]string, error) {
	if filepath.IsAbs(relPath) {
		return nil, fmt.Errorf("access denied: path %q must be relative", relPath)
	}
	clean := filepath.Clean(relPath)
	if clean == "." || clean == "" {
		return nil, fmt.Errorf("access denied: empty path")
	}
	parts := strings.Split(clean, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." || p == "" {
			return nil, fmt.Errorf("access denied: path %q escapes the base directory", relPath)
		}
	}
	return parts, nil
}

// SecureOpenBeneath opens (and, per flags, creates/truncates/appends) the file at
// baseDir/relPath, refusing to follow a symlink at ANY path component -- not just the
// final one. It walks relPath component-by-component via openat(2) relative to the
// file descriptor of the directory opened for the PREVIOUS component, passing
// O_NOFOLLOW|O_DIRECTORY for every intermediate component and O_NOFOLLOW for the leaf.
// This closes the TOCTOU gap a plain "validate path string, then os.OpenFile(path,
// ...O_NOFOLLOW)" leaves open: a symlink planted at a not-yet-existing intermediate
// component (one no string-level check could have resolved) is refused outright
// (ELOOP), not followed.
func SecureOpenBeneath(baseDir, relPath string, flags int, perm os.FileMode) (*os.File, error) {
	parts, err := safeRelComponents(relPath)
	if err != nil {
		return nil, err
	}

	dirFd, err := unix.Open(baseDir, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open base directory %q: %w", baseDir, err)
	}

	for _, component := range parts[:len(parts)-1] {
		childFd, oerr := unix.Openat(dirFd, component, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY, 0)
		_ = unix.Close(dirFd)
		if oerr != nil {
			if errors.Is(oerr, unix.ELOOP) {
				return nil, fmt.Errorf("access denied: path component %q of %q is a symlink", component, relPath)
			}
			return nil, fmt.Errorf("open path component %q of %q: %w", component, relPath, oerr)
		}
		dirFd = childFd
	}

	leaf := parts[len(parts)-1]
	fd, oerr := unix.Openat(dirFd, leaf, flags|unix.O_NOFOLLOW, uint32(perm))
	_ = unix.Close(dirFd)
	if oerr != nil {
		if errors.Is(oerr, unix.ELOOP) {
			return nil, fmt.Errorf("access denied: %q is a symlink", filepath.Join(baseDir, relPath))
		}
		return nil, oerr
	}

	return os.NewFile(uintptr(fd), filepath.Join(baseDir, relPath)), nil
}

// SecureCreateFileHandle opens a NEW file at baseDir/path for writing and returns the
// open *os.File, for callers that stream output (a JSON encoder, a report writer)
// rather than write a single already-assembled []byte. O_EXCL + the per-component
// O_NOFOLLOW walk: refuses to create through a symlink at any path component, and
// refuses to write through (or replace) a pre-existing path.
func SecureCreateFileHandle(baseDir, path string, perm os.FileMode) (*os.File, error) {
	if _, err := resolveInside(baseDir, path); err != nil {
		return nil, err
	}
	f, err := SecureOpenBeneath(baseDir, path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, perm) // #nosec G304 -- path validated inside baseDir by resolveInside + SecureOpenBeneath's per-component O_NOFOLLOW walk; O_EXCL refuses a pre-existing path
	if err != nil {
		return nil, err
	}
	if cerr := f.Chmod(perm); cerr != nil {
		_ = f.Close()
		return nil, cerr
	}
	return f, nil
}
