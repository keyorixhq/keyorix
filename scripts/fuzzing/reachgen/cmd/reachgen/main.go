// Command reachgen enumerates the exported third-party functions Keyorix code
// actually calls with attacker/operator-influenced arguments, ranks the
// UNCOVERED ones, and emits first-draft fuzz harness skeletons for the
// top-ranked fuzzable leads.
//
// It is offline and read-only. Output:
//
//	reachgen -patterns ./... -top 40 -md ranked.md -out /tmp/drafts
//
// -md writes the ranked markdown table (Phase 0 deliverable). -out writes one
// draft harness .txt per fuzzable uncovered lead (reviewed and red-proofed by
// hand before trust — a lead generator, not a gate).
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/scripts/fuzzing/reachgen"
)

func main() {
	var (
		patterns       = flag.String("patterns", "./...", "comma-separated go/packages load patterns")
		dir            = flag.String("dir", ".", "module directory to scan")
		top            = flag.Int("top", 40, "how many ranked uncovered entries to print")
		mdPath         = flag.String("md", "", "write ranked markdown table here (default: stdout)")
		outDir         = flag.String("out", "", "if set, emit draft harness skeletons here")
		coverDir       = flag.String("coverroot", ".", "root to scan for existing Fuzz test files")
		includeCovered = flag.Bool("include-covered", false, "include already-covered entries in the table")
	)
	flag.Parse()

	modulePrefix, err := modulePath(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reachgen: cannot read module path:", err)
		os.Exit(1)
	}

	cfg := reachgen.Config{
		ModulePrefix: modulePrefix,
		Patterns:     splitComma(*patterns),
		Dir:          *dir,
		Env:          os.Environ(),
	}
	res, err := reachgen.Scan(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reachgen: scan failed:", err)
		os.Exit(1)
	}

	cover := buildCoverage(*coverDir)
	reachgen.MarkCovered(res.Entries, cover)

	// Filter to untrusted-reachable entries.
	var untrusted []reachgen.Entry
	for _, e := range res.Entries {
		if e.UntrustedSites() == 0 {
			continue
		}
		if e.Covered && !*includeCovered {
			continue
		}
		untrusted = append(untrusted, e)
	}

	md := renderMarkdown(untrusted, *top, len(res.Entries), res.LoadErrors)
	if *mdPath != "" {
		if err := os.WriteFile(*mdPath, []byte(md), 0o644); err != nil { // #nosec G306 -- generated report, not a secret
			fmt.Fprintln(os.Stderr, "reachgen: write md:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "reachgen: wrote %s (%d untrusted entries, %d load diagnostics)\n", *mdPath, len(untrusted), len(res.LoadErrors))
	} else {
		fmt.Print(md)
	}

	if *outDir != "" {
		n := emitDrafts(untrusted, *outDir, *top)
		fmt.Fprintf(os.Stderr, "reachgen: emitted %d draft skeleton(s) to %s\n", n, *outDir)
	}
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func modulePath(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "go.mod")) // #nosec G304 -- developer tool reads the scanned module go.mod
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}
	return "", fmt.Errorf("no module line in go.mod")
}

// buildCoverage walks *_test.go files that declare a FuzzXxx and records, per
// imported third-party package, the lower-cased identifier tokens that appear
// in the file. A loose hint, re-checked by hand (see reachgen doc).
func buildCoverage(root string) map[string]map[string]bool {
	cover := map[string]map[string]bool{}
	fset := token.NewFileSet()
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "testdata" || base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		hasFuzz := false
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(fd.Name.Name, "Fuzz") {
				hasFuzz = true
				break
			}
		}
		if !hasFuzz {
			return nil
		}
		// Imports (strip quotes/alias).
		imports := map[string]bool{}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			imports[p] = true
		}
		// Tokens.
		toks := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				toks[strings.ToLower(id.Name)] = true
			}
			return true
		})
		for p := range imports {
			m := cover[p]
			if m == nil {
				m = map[string]bool{}
				cover[p] = m
			}
			for t := range toks {
				m[t] = true
			}
		}
		return nil
	})
	return cover
}

func renderMarkdown(entries []reachgen.Entry, top, totalEntries int, loadErrs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# reachgen — third-party entry points Keyorix actually calls on untrusted input\n\n")
	fmt.Fprintf(&b, "Total distinct third-party exported funcs called: %d. ", totalEntries)
	fmt.Fprintf(&b, "Shown: top %d UNCOVERED entries with at least one untrusted-provenance call site.\n\n", min(top, len(entries)))
	fmt.Fprintf(&b, "| # | Module | Package | Function | Sites | Untrusted | Provenance | Fuzzable |\n")
	fmt.Fprintf(&b, "|---|--------|---------|----------|------:|----------:|------------|:--------:|\n")
	n := min(top, len(entries))
	for i := range n {
		e := entries[i]
		fz := "no"
		if e.Fuzzable {
			fz = "yes"
		}
		fmt.Fprintf(&b, "| %d | %s | %s | `%s%s` | %d | %d | %s | %s |\n",
			i+1, e.Module, shortPkg(e.Pkg, e.Module), e.Func, e.Sig,
			len(e.Sites), e.UntrustedSites(), provString(e.ProvAgg), fz)
	}
	if len(loadErrs) > 0 {
		fmt.Fprintf(&b, "\n_%d package load diagnostic(s) (offline/partial build); counts are a floor, not a ceiling._\n", len(loadErrs))
	}
	return b.String()
}

func shortPkg(pkg, mod string) string {
	if mod != "" && strings.HasPrefix(pkg, mod) {
		rest := strings.TrimPrefix(pkg, mod)
		if rest == "" {
			return "·"
		}
		return strings.TrimPrefix(rest, "/")
	}
	return pkg
}

func provString(agg map[reachgen.Provenance]int) string {
	order := []reachgen.Provenance{reachgen.ProvRequest, reachgen.ProvUpload, reachgen.ProvConfig, reachgen.ProvBackend}
	var parts []string
	for _, p := range order {
		if agg[p] > 0 {
			parts = append(parts, fmt.Sprintf("%s×%d", p, agg[p]))
		}
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, ", ")
}

// emitDrafts writes a reviewable harness skeleton per fuzzable entry.
func emitDrafts(entries []reachgen.Entry, outDir string, top int) int {
	if err := os.MkdirAll(outDir, 0o755); err != nil { // #nosec G301 -- generated draft directory for a developer tool, not a secret
		fmt.Fprintln(os.Stderr, "reachgen: mkdir out:", err)
		return 0
	}
	n := 0
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].UntrustedSites() > entries[j].UntrustedSites()
	})
	for _, e := range entries {
		if n >= top {
			break
		}
		if !e.Fuzzable {
			continue
		}
		name := draftName(e)
		path := filepath.Join(outDir, name+".txt")
		if err := os.WriteFile(path, []byte(draftSource(e, name)), 0o644); err != nil { // #nosec G306 -- generated draft, not a secret
			continue
		}
		n++
	}
	return n
}

func draftName(e reachgen.Entry) string {
	base := e.Func
	base = strings.ReplaceAll(base, ".", "_")
	return "Fuzz" + base
}

func draftSource(e reachgen.Entry, name string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// DRAFT fuzz harness skeleton — reachgen lead, NOT trusted until red-proofed.\n")
	fmt.Fprintf(&b, "//\n")
	fmt.Fprintf(&b, "// Third-party entry point: %s.%s%s\n", e.Pkg, e.Func, e.Sig)
	fmt.Fprintf(&b, "// Module:   %s\n", e.Module)
	fmt.Fprintf(&b, "// Call sites in Keyorix (%d, %d untrusted):\n", len(e.Sites), e.UntrustedSites())
	shown := 0
	for _, s := range e.Sites {
		if shown >= 6 {
			fmt.Fprintf(&b, "//   ... and %d more\n", len(e.Sites)-shown)
			break
		}
		fmt.Fprintf(&b, "//   %s/%s:%d in %s  prov=%v\n", s.Pkg, s.File, s.Line, s.Func, s.Prov)
		shown++
	}
	fmt.Fprintf(&b, "//\n")
	fmt.Fprintf(&b, "// Param kinds: %v\n", e.Params)
	fmt.Fprintf(&b, "// TODO(reviewer): choose a SOUND oracle (round-trip / differential / bounded-work),\n")
	fmt.Fprintf(&b, "// NOT panic-only. State what it does NOT verify. Red-proof it. Then rename to\n")
	fmt.Fprintf(&b, "// <pkg>_%s_test.go in the target package and add a targets.d/ conf.\n", strings.ToLower(name))
	fmt.Fprintf(&b, "\npackage DRAFT\n\n")
	fmt.Fprintf(&b, "import (\n\t\"testing\"\n\n\t\"%s\"\n)\n\n", e.Pkg)
	fmt.Fprintf(&b, "func %s(f *testing.F) {\n", name)
	fmt.Fprintf(&b, "\tf.Fuzz(func(t *testing.T, data []byte) {\n")
	fmt.Fprintf(&b, "\t\t// Synthesise %s from `data`, call %s, assert the chosen oracle.\n", e.Sig, e.Func)
	fmt.Fprintf(&b, "\t\t_ = data\n")
	fmt.Fprintf(&b, "\t})\n}\n")
	return b.String()
}
