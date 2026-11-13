package main

import (
	"io"
	"os"
	"path/filepath"
)

// copyModule recursively copies the module rooted at src into dst, skipping
// version-control and heavyweight non-Go trees. The real checkout is never
// touched: the tool only ever mutates files under dst. Symlinks are copied as
// regular files of their target contents when resolvable, else skipped.
func copyModule(src, dst string) error {
	src = filepath.Clean(src)
	skipDir := map[string]bool{
		".git": true, "node_modules": true, ".idea": true, ".vscode": true,
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
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
			// Resolve and copy the content if it points at a regular file.
			real, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil
			}
			ri, err := os.Stat(real)
			if err != nil || ri.IsDir() {
				return nil
			}
			return copyFile(real, target, 0o644)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- src is a path found by this tool's own walk of the target package
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm) // #nosec G304 -- dst is under the tool's own scratch copy
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
