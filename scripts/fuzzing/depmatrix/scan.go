// scan.go — walk the repository and build import maps for the dep matrix.
//
// WHAT THIS SCANS: every .go file in the repo tree.
//   - Non-test files: used to build the production import graph (REACH).
//   - Fuzz test files (*_test.go containing func FuzzXxx): used to build
//     the fuzz coverage graph (FUZZ).
//
// WHAT THIS DOES NOT DO:
//   - Does not follow transitive imports across package boundaries (1-hop only).
//   - Does not use type information; import matching is string-prefix only.
//   - Does not skip build-tag-excluded files (such files may be parsed but
//     their build constraints are not evaluated — a file ignored by `go build`
//     may still appear as an importer).
//   - Does not distinguish between _test and external test packages within
//     the same directory.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// scanResult holds the full import picture derived from walking the repo.
type scanResult struct {
	// prodImports: pkg-dir → set of external modules imported from non-test files.
	// Keys are repo-relative package dirs (e.g. "internal/crypto/gcpkms").
	// Values are the module-path prefixes of imported external packages
	// (e.g. "cloud.google.com/go/kms").
	prodImports map[string]map[string]bool

	// testImports: pkg-dir → set of external modules imported from *_test.go files.
	// Used to distinguish UNUSED (never imported) from TOOLING (test-only import).
	testImports map[string]map[string]bool

	// fuzzTargets: one entry per file that contains at least one func FuzzXxx.
	fuzzTargets []fuzzTarget

	// ownPkgForModule[mod] = set of repo-relative package dirs whose non-test
	// files directly import at least one package from mod.
	ownPkgForModule map[string][]string

	// modPaths is the set of all module paths found in the repo's go.mod files.
	// Used to distinguish "own" packages from external ones.
	ownModules []string

	// skipped counts .go files and directories the walk could not read or
	// parse. A skipped importer can only lower REACH (hide a gap), so the
	// count is reported in the run summary.
	skipped int
}

// fuzzTarget describes one file that declares at least one func FuzzXxx.
type fuzzTarget struct {
	File      string   // repo-relative file path
	PkgDir    string   // repo-relative package dir
	FuzzFuncs []fuzzFn // all Fuzz functions in this file
	Imports   []string // external module paths directly imported by this file
	OwnPkgs   []string // repo-relative packages from own modules imported by this file
}

// fuzzFn is one Fuzz function declaration.
type fuzzFn struct {
	Name string
	Line int
}

var skipDirsDepmatrix = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	"dist": true, "build": true, ".next": true,
	".claude": true, ".scratch": true, "testdata": true,
}

const maxFileSizeDepmatrix = 4 << 20 // 4 MiB

// scanRepo walks every .go file under root and builds a scanResult.
// goModPaths is the list of repo-relative go.mod paths (used to register ownModules).
func scanRepo(root string, goModPaths []string) (*scanResult, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	res := &scanResult{
		prodImports:     map[string]map[string]bool{},
		testImports:     map[string]map[string]bool{},
		ownPkgForModule: map[string][]string{},
	}

	// Collect own module paths from all go.mod files.
	for _, rel := range goModPaths {
		abs := filepath.Join(rootAbs, filepath.FromSlash(rel))
		mp := goModModulePath(abs)
		if mp != "" {
			res.ownModules = append(res.ownModules, mp)
		}
	}

	fset := token.NewFileSet()

	err = filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			res.skipped++
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if skipDirsDepmatrix[name] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() > maxFileSizeDepmatrix {
			res.skipped++
			return nil
		}
		rel, _ := filepath.Rel(rootAbs, path)
		rel = filepath.ToSlash(rel)
		return scanFile(fset, path, rel, res)
	})
	if err != nil {
		return nil, err
	}

	// Build ownPkgForModule: for each external module, collect which of our
	// packages import it.
	for pkg, mods := range res.prodImports {
		for mod := range mods {
			res.ownPkgForModule[mod] = append(res.ownPkgForModule[mod], pkg)
		}
	}
	// Sort for determinism.
	for mod := range res.ownPkgForModule {
		sortStrings(res.ownPkgForModule[mod])
	}

	return res, nil
}

// scanFile parses one .go file and updates res.
func scanFile(fset *token.FileSet, absPath, relPath string, res *scanResult) error {
	src, err := os.ReadFile(absPath) // #nosec G304 -- developer tool scans repo source
	if err != nil {
		res.skipped++
		return nil
	}
	// Skip files with the //go:build ignore constraint quickly.
	if containsBuildIgnore(src) {
		return nil
	}
	f, err := parser.ParseFile(fset, absPath, src, parser.SkipObjectResolution)
	if err != nil {
		res.skipped++ // unparseable files (build-tag fragments, etc.)
		return nil
	}
	isTest := strings.HasSuffix(relPath, "_test.go")
	pkgDir := filepath.ToSlash(filepath.Dir(relPath))

	// Collect imports, split into external modules and own-module packages.
	var extMods []string // external module-path prefixes imported by this file
	var ownPkgs []string // own-module package paths imported by this file
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if p == "C" {
			continue
		}
		if own := matchOwnModule(p, res.ownModules); own != "" {
			// Convert module+package path to repo-relative dir.
			repoRel := ownPkgToRepoRel(p, own)
			if repoRel != "" {
				ownPkgs = append(ownPkgs, repoRel)
			}
		} else if !isStdlib(p) {
			extMods = append(extMods, modulePrefix(p))
		}
	}
	dedupeStrings(&extMods)
	dedupeStrings(&ownPkgs)

	if !isTest {
		if _, ok := res.prodImports[pkgDir]; !ok {
			res.prodImports[pkgDir] = map[string]bool{}
		}
		for _, m := range extMods {
			res.prodImports[pkgDir][m] = true
		}
		return nil
	}

	// For test files: record all external imports for TOOLING classification,
	// then look for Fuzz functions.
	if _, ok := res.testImports[pkgDir]; !ok {
		res.testImports[pkgDir] = map[string]bool{}
	}
	for _, m := range extMods {
		res.testImports[pkgDir][m] = true
	}

	var fuzzFns []fuzzFn
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "Fuzz") || !hasFParam(fn) {
			continue
		}
		pos := fset.Position(fn.Pos())
		fuzzFns = append(fuzzFns, fuzzFn{Name: fn.Name.Name, Line: pos.Line})
	}
	if len(fuzzFns) > 0 {
		res.fuzzTargets = append(res.fuzzTargets, fuzzTarget{
			File:      relPath,
			PkgDir:    pkgDir,
			FuzzFuncs: fuzzFns,
			Imports:   extMods,
			OwnPkgs:   ownPkgs,
		})
	}
	return nil
}

// containsBuildIgnore reports whether src starts with a //go:build ignore constraint.
func containsBuildIgnore(src []byte) bool {
	content := string(src)
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "//") {
			if strings.Contains(line, "go:build ignore") {
				return true
			}
			if strings.Contains(line, "+build ignore") {
				return true
			}
			continue
		}
		break // non-comment, non-blank line reached
	}
	return false
}

// matchOwnModule returns the own-module path that is a prefix of pkgPath,
// or "" if pkgPath belongs to an external module.
func matchOwnModule(pkgPath string, ownModules []string) string {
	for _, mod := range ownModules {
		if pkgPath == mod || strings.HasPrefix(pkgPath, mod+"/") {
			return mod
		}
	}
	return ""
}

// ownPkgToRepoRel converts an own-module package path to a repo-relative dir.
// e.g. "github.com/keyorixhq/keyorix/internal/core" with own module
// "github.com/keyorixhq/keyorix" → "internal/core".
// For a submodule like "github.com/keyorixhq/keyorix/cli/cmd" with own module
// "github.com/keyorixhq/keyorix/cli" → "cli/cmd".
func ownPkgToRepoRel(pkgPath, ownMod string) string {
	// Find the repo-relative module root dir.
	// The module path is ownMod; figure out what directory it maps to.
	// For the root module ("github.com/keyorixhq/keyorix"), packages live at
	// their sub-path relative to the repo root.
	// For submodules ("github.com/keyorixhq/keyorix/cli"), packages live under "cli/".
	rootModPrefix := rootModuleForMod(ownMod)
	var relToMod string
	if pkgPath == ownMod {
		relToMod = "."
	} else {
		relToMod = pkgPath[len(ownMod)+1:]
	}
	if rootModPrefix == "" {
		return relToMod
	}
	if relToMod == "." {
		return rootModPrefix
	}
	return rootModPrefix + "/" + relToMod
}

// rootModuleForMod maps a submodule path to its repo-relative directory.
// e.g. "github.com/keyorixhq/keyorix/cli" → "cli".
// The root module "github.com/keyorixhq/keyorix" → "".
// This is determined by the convention that nested go.mod lives at <reldir>/go.mod.
// We approximate by stripping the longest common prefix with the root module.
var knownRootModPrefix = "github.com/keyorixhq/keyorix"

func rootModuleForMod(ownMod string) string {
	if ownMod == knownRootModPrefix {
		return ""
	}
	if rest, ok := strings.CutPrefix(ownMod, knownRootModPrefix+"/"); ok {
		return rest
	}
	// Unknown module structure — use the last path element of the module path.
	parts := strings.Split(ownMod, "/")
	return parts[len(parts)-1]
}

// modulePrefix returns the module-path prefix for an import path.
// A module path is typically the first 2-4 segments of the package path.
// We use a best-effort heuristic: for golang.org/x/*, return golang.org/x/<pkg>;
// for github.com/foo/bar/sub/pkg, return github.com/foo/bar.
// The caller deduplicates and matches against the dep list later.
//
// Since we match against the known module list from go.mod, false positives
// (over-short prefix) are filtered by the caller.
func modulePrefix(importPath string) string {
	return importPath // return the full import path; caller strips subpackage suffix
}

// isStdlib reports whether an import path is from the Go standard library.
// Standard library packages have no dot in the first path element.
func isStdlib(p string) bool {
	first, _, _ := strings.Cut(p, "/")
	return !strings.Contains(first, ".")
}

// hasFParam returns true if fn's first parameter is *testing.F.
func hasFParam(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return false
	}
	t := fn.Type.Params.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.SelectorExpr:
			return x.Sel.Name == "F"
		case *ast.Ident:
			return x.Name == "F"
		default:
			return false
		}
	}
}

// sortStrings sorts a string slice in place.
func sortStrings(s []string) {
	if len(s) <= 1 {
		return
	}
	// Simple insertion sort for small slices; use stdlib for larger ones.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// dedupeStrings removes duplicates from a string slice in place, then sorts it.
func dedupeStrings(s *[]string) {
	sortStrings(*s)
	out := (*s)[:0]
	for i, v := range *s {
		if i == 0 || v != (*s)[i-1] {
			out = append(out, v)
		}
	}
	*s = out
}
