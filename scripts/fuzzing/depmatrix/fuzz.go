// fuzz.go — FUZZ class assignment and evidence collection for each dependency.
//
// FUZZ classes:
//   - DIRECT: a Fuzz function in a *_test.go file imports the module or calls
//     an exported function of it.
//   - WRAPPED: a Fuzz function drives a package from this repo that calls the
//     module; the package and call-site file are named in the evidence.
//   - TARGETS.D: the module is covered only by an entry in
//     scripts/fuzzing/targets.d/*.conf; the import chain could not be verified
//     statically (e.g. coverage via reflection or generated code).
//   - NONE: no fuzz coverage found.
//
// WHAT THIS DOES NOT DO:
//   - Does not verify that listed fuzz targets still compile or run in CI.
//   - Does not evaluate oracle quality (a no-panic oracle is weaker than a
//     differential one; both are classified DIRECT or WRAPPED here).
//   - Does not follow import chains beyond 1 hop (a Fuzz test → our package →
//     dep is WRAPPED; a Fuzz test → our package → another package → dep is not
//     detected).
//   - WRAPPED evidence names the first matching (fuzz-file, own-pkg) pair only;
//     other pairs that also cover the dep are not exhaustively listed.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// fuzzClass is one of the four FUZZ values.
type fuzzClass string

const (
	fuzzDirect   fuzzClass = "DIRECT"
	fuzzWrapped  fuzzClass = "WRAPPED"
	fuzzTargetsD fuzzClass = "TARGETS.D"
	fuzzNone     fuzzClass = "NONE"
)

// classifyFuzz returns the FUZZ class and up to 3 evidence strings for dep.
//
// Evidence format:
//   - DIRECT:   "path/to/file.go:FuzzFuncName"
//   - WRAPPED:  "path/to/file.go:FuzzFuncName (via ownPkg)"
//   - TARGETS.D: "scripts/fuzzing/targets.d/<file>"
//   - NONE:     (empty)
func classifyFuzz(dep string, sr *scanResult, targetsD []targetsDEntry) (fuzzClass, []string) {
	var directEv, wrappedEv []string

	for i := range sr.fuzzTargets {
		ft := &sr.fuzzTargets[i]

		// DIRECT: fuzz file imports the dep module directly.
		if importsDep(ft.Imports, dep) {
			for j := range ft.FuzzFuncs {
				if len(directEv) < 3 {
					directEv = append(directEv, fmt.Sprintf("%s:%s", ft.File, ft.FuzzFuncs[j].Name))
				}
			}
			continue
		}

		// WRAPPED: fuzz file imports an own-module package that imports dep.
		for _, ownPkg := range ft.OwnPkgs {
			if !hasMod(sr.prodImports[ownPkg], dep) {
				continue
			}
			for j := range ft.FuzzFuncs {
				if len(wrappedEv) < 3 {
					wrappedEv = append(wrappedEv, fmt.Sprintf("%s:%s (via %s)", ft.File, ft.FuzzFuncs[j].Name, ownPkg))
				}
			}
			break
		}
	}

	if len(directEv) > 0 {
		return fuzzDirect, directEv
	}
	if len(wrappedEv) > 0 {
		return fuzzWrapped, wrappedEv
	}

	// TARGETS.D: check if any targets.d conf file names this dep.
	for _, td := range targetsD {
		if strings.Contains(td.PkgPath, "/"+strings.ReplaceAll(depShortName(dep), "/", "-")) ||
			strings.Contains(td.PkgPath, strings.ReplaceAll(depShortName(dep), "/", "-")) {
			return fuzzTargetsD, []string{td.ConfFile}
		}
	}

	return fuzzNone, nil
}

// importsDep reports whether any of the import paths matches dep as a module prefix.
func importsDep(imports []string, dep string) bool {
	for _, imp := range imports {
		if imp == dep || strings.HasPrefix(imp, dep+"/") {
			return true
		}
	}
	return false
}

// hasMod reports whether the set contains any path that is or is under dep.
func hasMod(mods map[string]bool, dep string) bool {
	for imp := range mods {
		if imp == dep || strings.HasPrefix(imp, dep+"/") {
			return true
		}
	}
	return false
}

// depShortName returns the last 2 path elements of a module path.
// e.g. "cloud.google.com/go/kms" → "go/kms", "github.com/go-chi/chi/v5" → "chi/v5"
func depShortName(dep string) string {
	parts := strings.Split(dep, "/")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return dep
}

// targetsDEntry is one entry read from scripts/fuzzing/targets.d/*.conf.
type targetsDEntry struct {
	ConfFile string // repo-relative path to the .conf file
	PkgPath  string // Go package path (first field in the conf)
	FuncName string // fuzz function name (second field)
}

// loadTargetsD reads all *.conf files from scripts/fuzzing/targets.d/ and
// returns a list of entries.
func loadTargetsD(root string) ([]targetsDEntry, error) {
	dir := filepath.Join(root, "scripts", "fuzzing", "targets.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []targetsDEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		absPath := filepath.Join(dir, e.Name())
		relPath := "scripts/fuzzing/targets.d/" + e.Name()
		td, err := parseTargetsDConf(absPath, relPath)
		if err != nil {
			continue
		}
		out = append(out, td...)
	}
	return out, nil
}

// parseTargetsDConf parses one targets.d conf file. The non-comment, non-blank
// lines have the format: <go-package>|<FuzzFuncName>|<duration>.
func parseTargetsDConf(absPath, relPath string) ([]targetsDEntry, error) {
	data, err := os.ReadFile(absPath) // #nosec G304 -- reads known targets.d config file
	if err != nil {
		return nil, err
	}
	var out []targetsDEntry
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			continue
		}
		out = append(out, targetsDEntry{
			ConfFile: relPath,
			PkgPath:  strings.TrimSpace(parts[0]),
			FuncName: strings.TrimSpace(parts[1]),
		})
	}
	return out, nil
}

// fuzzTargetInDir loads fuzz targets from a directory tree and returns
// a summary of which directories contain fuzz targets.
// This is used only for diagnostics; the main coverage is in sr.fuzzTargets.
func fuzzTargetDirsInRepo(root string) (map[string]bool, error) {
	dirs := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if skipDirsDepmatrix[filepath.Base(filepath.Dir(path))] {
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		dirs[filepath.ToSlash(filepath.Dir(rel))] = true
		return nil
	})
	return dirs, err
}
