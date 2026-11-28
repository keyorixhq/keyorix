// gomod.go — parse go.mod files to extract direct module dependencies.
package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DirectDep is one explicitly-required (non-indirect) module.
type DirectDep struct {
	Module  string // e.g. cloud.google.com/go/kms
	Version string // e.g. v1.36.0
	GoMod   string // repo-relative path to the go.mod that declared it
}

// findGoMods returns the repo-relative paths of every go.mod under root.
// It includes the root go.mod and every go.mod in a subdirectory.
func findGoMods(root string) ([]string, error) {
	var paths []string
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			switch name {
			case ".git", ".claude", ".scratch", "node_modules", "vendor", "testdata", "dist", "build":
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		rel, _ := filepath.Rel(rootAbs, path)
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	return paths, err
}

// collectDirectDeps reads every go.mod in goModPaths (all repo-relative) and
// returns all direct (non-indirect) requires, deduplicating by module path and
// keeping the first occurrence.
func collectDirectDeps(root string, goModPaths []string) ([]DirectDep, error) {
	seen := map[string]bool{}
	var deps []DirectDep
	for _, rel := range goModPaths {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		from, err := parseDirectDepsFile(abs, rel)
		if err != nil {
			return nil, err
		}
		for _, d := range from {
			if seen[d.Module] {
				continue
			}
			seen[d.Module] = true
			deps = append(deps, d)
		}
	}
	return deps, nil
}

// parseDirectDepsFile returns direct (non-indirect) requires from one go.mod file.
func parseDirectDepsFile(absPath, relPath string) ([]DirectDep, error) {
	data, err := os.ReadFile(absPath) // #nosec G304 -- developer tool reads repo go.mod files
	if err != nil {
		return nil, err
	}
	return parseGoModDirect(string(data), relPath), nil
}

// parseGoModDirect extracts direct requires from go.mod content.
// It handles both single-line `require X v` and block `require (\n X v\n)` forms.
func parseGoModDirect(content, goModRel string) []DirectDep {
	var deps []DirectDep
	inBlock := false
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if inBlock {
			dep := parseRequireLine(line, goModRel)
			if dep != nil {
				deps = append(deps, *dep)
			}
			continue
		}
		// Single-line require
		if rest, ok := strings.CutPrefix(line, "require "); ok {
			dep := parseRequireLine(strings.TrimSpace(rest), goModRel)
			if dep != nil {
				deps = append(deps, *dep)
			}
		}
	}
	return deps
}

// parseRequireLine parses a single require line like "cloud.google.com/go/kms v1.36.0"
// or "github.com/foo/bar v1.2.3 // indirect". Returns nil for indirect deps or bad lines.
func parseRequireLine(line, goModRel string) *DirectDep {
	// Strip inline comment
	if idx := strings.Index(line, "//"); idx >= 0 {
		comment := strings.TrimSpace(line[idx+2:])
		if strings.Contains(comment, "indirect") {
			return nil
		}
		line = strings.TrimSpace(line[:idx])
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	return &DirectDep{Module: parts[0], Version: parts[1], GoMod: goModRel}
}

// goModModulePath returns the module path declared in a go.mod file.
func goModModulePath(absPath string) string {
	data, err := os.ReadFile(absPath) // #nosec G304 -- developer tool
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(strings.SplitN(rest, " ", 2)[0])
		}
	}
	return ""
}
