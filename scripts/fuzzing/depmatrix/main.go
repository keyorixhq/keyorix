// Command depmatrix generates the dependency-to-fuzz-coverage matrix for the
// Keyorix repository.
//
// Usage:
//
//	go run ./scripts/fuzzing/depmatrix [flags]
//
// Flags:
//
//	-root string    repo root directory (default: auto-detected from $PWD or ../../..)
//	-out-md string  output path for the markdown matrix (default: .scratch/depmatrix/DEP-FUZZ-MATRIX.md)
//	-out-json string output path for the JSON matrix  (default: .scratch/depmatrix/dep-fuzz-matrix.json)
//
// WHAT THE PROGRAM SCANS:
//
//   - Every go.mod under root (root module + nested modules found by git ls-files).
//   - Every .go file under root for import analysis.
//   - scripts/fuzzing/targets.d/*.conf for the declared fuzz targets.
//
// WHAT THE PROGRAM DOES NOT DO (stated explicitly so callers know what to trust):
//
//   - Does not run 'go list', the Go compiler, or any external process.
//   - Does not evaluate Go build constraints; a build-tag-excluded file may
//     still appear as an importer.
//   - Does not follow transitive imports across package boundaries (1 hop only
//     for both REACH and WRAPPED).
//   - Does not verify that listed fuzz targets compile, run, or produce
//     meaningful coverage.
//   - Does not evaluate oracle quality (a no-panic oracle and a differential
//     oracle are both DIRECT/WRAPPED here).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	var root, outMD, outJSON string
	flag.StringVar(&root, "root", "", "repo root (default: auto-detect from cwd)")
	flag.StringVar(&outMD, "out-md", ".scratch/depmatrix/DEP-FUZZ-MATRIX.md", "output markdown path (relative to root; .scratch/ is git-ignored, the matrix is generated, not committed)")
	flag.StringVar(&outJSON, "out-json", ".scratch/depmatrix/dep-fuzz-matrix.json", "output JSON path (relative to root; .scratch/ is git-ignored)")
	flag.Parse()

	if root == "" {
		auto, err := findRepoRoot()
		if err != nil {
			log.Fatalf("cannot locate repo root (no go.mod with module declaration found): %v", err)
		}
		root = auto
	}
	root, _ = filepath.Abs(root)

	rows, rootMod, err := generate(root)
	if err != nil {
		log.Fatalf("generate: %v", err)
	}

	mdPath := filepath.Join(root, filepath.FromSlash(outMD))
	if err := writeMarkdown(rows, mdPath); err != nil {
		log.Fatalf("write markdown: %v", err)
	}
	jsonPath := filepath.Join(root, filepath.FromSlash(outJSON))
	if err := writeJSON(rows, rootMod, jsonPath); err != nil {
		log.Fatalf("write JSON: %v", err)
	}

	counts := buildCounts(rows)
	fmt.Printf("depmatrix: %d direct deps  UNTRUSTED=%d TRUSTED-ONLY=%d TOOLING=%d UNUSED=%d  DIRECT=%d WRAPPED=%d TARGETS.D=%d NONE=%d  gaps(UNTRUSTED+NONE)=%d\n",
		counts.Total,
		counts.ByReach[string(reachUntrusted)],
		counts.ByReach[string(reachTrustedOnly)],
		counts.ByReach[string(reachTooling)],
		counts.ByReach[string(reachUnused)],
		counts.ByFuzz[string(fuzzDirect)],
		counts.ByFuzz[string(fuzzWrapped)],
		counts.ByFuzz[string(fuzzTargetsD)],
		counts.ByFuzz[string(fuzzNone)],
		counts.UntrustedNone,
	)
	fmt.Printf("depmatrix: wrote %s\n", mdPath)
	fmt.Printf("depmatrix: wrote %s\n", jsonPath)
}

// generate builds the DepRow slice for root.
// Returns the rows sorted by module path, the root module path, and any error.
func generate(root string) ([]DepRow, string, error) {
	// 1. Find all go.mod files.
	goMods, err := findGoMods(root)
	if err != nil {
		return nil, "", fmt.Errorf("findGoMods: %w", err)
	}

	// 2. Parse direct deps from each go.mod.
	deps, err := collectDirectDeps(root, goMods)
	if err != nil {
		return nil, "", fmt.Errorf("collectDirectDeps: %w", err)
	}

	// 3. Walk source files to build import maps.
	sr, err := scanRepo(root, goMods)
	if err != nil {
		return nil, "", fmt.Errorf("scanRepo: %w", err)
	}

	if sr.skipped > 0 {
		fmt.Fprintf(os.Stderr, "depmatrix: %d go files/dirs could not be read or parsed and were skipped (a skipped importer can hide a gap)\n", sr.skipped)
	}

	// 4. Load targets.d conf files.
	targetsD, err := loadTargetsD(root)
	if err != nil {
		return nil, "", fmt.Errorf("loadTargetsD: %w", err)
	}

	// 5. Determine root module path from the repo root go.mod directly.
	rootMod := goModModulePath(filepath.Join(root, "go.mod"))

	// Build a set of own module paths to filter from the dep list.
	// cli/go.mod lists the root module as a direct dep via replace directive;
	// listing our own modules as deps would inflate the matrix with false entries.
	ownModSet := map[string]bool{}
	for _, m := range sr.ownModules {
		ownModSet[m] = true
	}

	// 6. Build rows, skipping deps that are own modules.
	rows := make([]DepRow, 0, len(deps))
	for _, dep := range deps {
		if ownModSet[dep.Module] {
			continue
		}
		row := buildRow(dep, sr, targetsD)
		rows = append(rows, row)
	}

	// 7. Sort by module path for determinism.
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Module < rows[j].Module
	})

	return rows, rootMod, nil
}

// buildRow constructs a DepRow for one direct dependency.
func buildRow(dep DirectDep, sr *scanResult, targetsD []targetsDEntry) DepRow {
	// Find non-test packages that import this module.
	var importingPkgs []string
	for pkg, mods := range sr.prodImports {
		for imp := range mods {
			if imp == dep.Module || strings.HasPrefix(imp, dep.Module+"/") {
				importingPkgs = append(importingPkgs, pkg)
				break
			}
		}
	}
	sortStrings(importingPkgs)

	top := topImporters(importingPkgs, 3)
	reach := classifyReach(importingPkgs)
	// If no production importers were found, check whether any *_test.go file
	// imports this module. If so, classify as TOOLING (test-only dep) rather than
	// UNUSED (never imported anywhere).
	if reach == reachUnused {
		for _, mods := range sr.testImports {
			for imp := range mods {
				if imp == dep.Module || strings.HasPrefix(imp, dep.Module+"/") {
					reach = reachTooling
					goto afterReachReclassify
				}
			}
		}
	afterReachReclassify:
	}
	fc, evidence := classifyFuzz(dep.Module, sr, targetsD)

	notes := manualNote(dep.Module)

	return DepRow{
		Module:      dep.Module,
		Version:     dep.Version,
		GoMod:       dep.GoMod,
		ImportCount: len(importingPkgs),
		TopPkgs:     top,
		Reach:       string(reach),
		Fuzz:        string(fc),
		Evidence:    evidence,
		Notes:       notes,
	}
}

// manualNote returns a hand-written note for deps that need extra context.
// All entries here are marked "manual" because they correct or supplement the
// static analysis. Each note says WHY the automatic classification might
// be incomplete.
func manualNote(mod string) string {
	notes := map[string]string{
		// gax-go is the gRPC retry/transport layer for GCP SDKs; reachable via gcpkms target.
		"github.com/googleapis/gax-go/v2": "manual: gRPC retry/transport layer for GCP SDKs; reached via fuzz/thirdparty/gcpkms (uses real KMS client)",
		// prometheus is only used as metrics reporter; not fed untrusted input.
		"github.com/prometheus/client_golang": "manual: metrics-only; no untrusted input reaches Prometheus call sites",
		"github.com/prometheus/client_model":  "manual: metrics model types only; no untrusted input",
		// porcupine is a linearizability checker used in tests only.
		"github.com/anishathalye/porcupine": "manual: test-only linearizability checker; not in production binary",
		// keyorix-sdks is our own SDK; classified as own code, not third-party.
		"github.com/keyorixhq/keyorix-sdks/go": "manual: Keyorix own SDK; treated as own code",
	}
	return notes[mod]
}

// findRepoRoot walks up from the working directory looking for a go.mod that
// declares a module path (not just any go.mod).
func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		candidate := filepath.Join(dir, "go.mod")
		if mp := goModModulePath(candidate); mp != "" {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("no go.mod found above %s", cwd)
}
