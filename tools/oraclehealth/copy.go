package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// copyMarker is written into every working copy that copyModule produces.
// run() refuses to mutate a module (-module) or reuse a destination (-work)
// that does not carry it, so the tool can only ever edit a directory it created
// itself. The claim "the real checkout is never edited" is therefore enforced,
// not asserted.
const copyMarker = ".oraclehealth-copy"

const copyMarkerBody = "created by tools/oraclehealth: a disposable working copy that the tool may mutate\n"

// resolvePath returns an absolute path with symlinks resolved. The path need not
// exist: the longest existing ancestor is resolved and the remainder appended.
func resolvePath(p string) (string, error) {
	cur, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rest := ""
	for {
		real, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(real, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", err
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// within reports whether path is equal to or inside dir (both absolute and
// symlink-resolved).
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// checkWorkDir refuses a -work destination that overlaps the source tree (equal,
// inside it, or containing it) or that is a non-empty directory the tool did not
// create. Both arguments must already be resolved with resolvePath.
func checkWorkDir(src, dst string) error {
	if within(dst, src) || within(src, dst) {
		return fmt.Errorf("-src %s and -work %s overlap (equal or one inside the other); choose a -work outside the source tree", src, dst)
	}
	entries, err := os.ReadDir(dst)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case len(entries) == 0:
		return nil
	}
	if _, err := os.Lstat(filepath.Join(dst, copyMarker)); err != nil {
		return fmt.Errorf("-work %s is not empty and has no %s marker: refusing to overwrite a directory this tool did not create", dst, copyMarker)
	}
	return nil
}

// checkModuleDir refuses a -module directory the tool may not mutate: it must
// carry the marker copyModule writes and must not be a version-controlled
// checkout.
func checkModuleDir(dir string) error {
	if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
		return fmt.Errorf("-module %s contains .git: it is a checkout, not a working copy; use -src to copy it", dir)
	}
	if _, err := os.Lstat(filepath.Join(dir, copyMarker)); err != nil {
		return fmt.Errorf("-module %s has no %s marker: it was not created by this tool; use -src to copy it", dir, copyMarker)
	}
	return nil
}

// copyModule recursively copies the module rooted at src into dst, skipping
// version-control and heavyweight non-Go trees, and stamps dst with copyMarker.
// The real checkout is never touched: the tool only ever mutates files under
// dst. dst must not overlap src. Files are written owner-only (the owner's
// execute bit is kept); a symlink is copied as a regular file of its target's
// contents only when the target resolves to a regular file inside src, else it
// is skipped.
func copyModule(src, dst string) error {
	src, err := resolvePath(src)
	if err != nil {
		return err
	}
	dst, err = resolvePath(dst)
	if err != nil {
		return err
	}
	if err := checkWorkDir(src, dst); err != nil {
		return err
	}
	skipDir := map[string]bool{
		".git": true, "node_modules": true, ".idea": true, ".vscode": true,
	}
	err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o750)
		}
		base := info.Name()
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			if skipDir[base] {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0o750)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// Copy the content only if it points at a regular file inside src.
			real, err := filepath.EvalSymlinks(path)
			if err != nil || !within(real, src) {
				return nil
			}
			ri, err := os.Stat(real)
			if err != nil || !ri.Mode().IsRegular() {
				return nil
			}
			return copyFile(real, target, ri.Mode().Perm())
		}
		if !info.Mode().IsRegular() || base == copyMarker {
			return nil
		}
		return copyFile(path, target, info.Mode().Perm())
	})
	if err != nil {
		return err
	}
	return writeFrom(strings.NewReader(copyMarkerBody), filepath.Join(dst, copyMarker), 0o600)
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- src is a path found by this tool's own walk of the target package
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	return writeFrom(in, dst, perm)
}

// writeFrom writes r to dst, owner-only: the owner's execute bit of perm is kept,
// group and other bits are dropped.
func writeFrom(r io.Reader, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm&0o700|0o600) // #nosec G304 -- dst is under the tool's own scratch copy
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
