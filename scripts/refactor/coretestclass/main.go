// Command coretestclass classifies the in-package test files of a Go package
// (default ./internal/core) as black-box or white-box, the analysis behind
// CORE-SPLIT-DESIGN-1 section 3.7 and the move waves of ADR-121.
//
// A test file is black-box when every package-level object, field and method of
// the package it uses is exported, or is declared in another test file that is
// itself black-box (the helper closure). -relax names unexported identifiers to
// treat as reachable (the design's "if c.storage/c.now were reachable" row:
// -relax storage,now).
//
// wave = black-box minus the files that must stay in the package (ADR-121
// decision 2): fuzz targets, testdata readers, Postgres-gated files, init()
// registries, source scanners (go/parser), and files declaring a test named by
// a ledger row (docs/security-closures.d, docs/adr-conformance-enforced*,
// <pkg>/INVARIANTS*).
//
// Output: one table row per set (files, lines, Test functions); -out <dir>
// writes each set's file list as <set>.txt for scripts/refactor/measure-core.sh.
//
// What it does not see: uses through reflection, //go:linkname or unsafe, and
// an exclusion signal spelled differently from the patterns in excludeReasons.
// It type-checks with the compiler's export data (go list -export), so the
// package and its test dependencies are compiled first.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type fileInfo struct {
	name      string
	lines     int
	tests     []string
	src       string
	direct    bool            // uses no unexported non-test object
	helpers   map[string]bool // other test files it uses objects of
	blackbox  bool
	excludeBy string
}

func main() {
	pkg := flag.String("pkg", "./internal/core", "package to classify")
	relax := flag.String("relax", "", "comma-separated unexported names to treat as reachable (e.g. storage,now)")
	out := flag.String("out", "", "directory to write <set>.txt file lists into")
	flag.Parse()
	if err := run(*pkg, *relax, *out, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "coretestclass:", err)
		os.Exit(1)
	}
}

func goList(args ...string) ([]byte, error) {
	cmd := exec.Command("go", append([]string{"list"}, args...)...) // #nosec G204 -- fixed "go list"; args are fixed flags plus the -pkg value the operator passed to this hand-run dev tool, no remote input
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func run(pkgPath, relax, outDir string, w io.Writer) error {
	_, _ = fmt.Fprintf(os.Stderr, "coretestclass: compiling %s and its test dependencies for export data...\n", pkgPath)
	raw, err := goList("-json", pkgPath)
	if err != nil {
		return err
	}
	var meta struct {
		Dir, ImportPath, Name string
		GoFiles, TestGoFiles  []string
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return err
	}
	exports := map[string]string{}
	raw, err = goList("-export", "-deps", "-test", "-f", "{{.ImportPath}}\t{{.Export}}", pkgPath)
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if p, e, ok := strings.Cut(line, "\t"); ok && e != "" && !strings.Contains(p, " ") {
			exports[p] = e
		}
	}

	fset := token.NewFileSet()
	var files []*ast.File
	testFiles := map[string]bool{}
	for _, n := range append(slices.Clone(meta.GoFiles), meta.TestGoFiles...) {
		f, err := parser.ParseFile(fset, filepath.Join(meta.Dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files = append(files, f)
	}
	for _, n := range meta.TestGoFiles {
		testFiles[n] = true
	}
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		e, ok := exports[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(e) // #nosec G304 -- export file named by go list
	})
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	tpkg, err := (&types.Config{Importer: imp}).Check(meta.ImportPath, fset, files, info)
	if err != nil {
		return fmt.Errorf("type-check %s: %w", meta.ImportPath, err)
	}

	relaxed := map[string]bool{}
	for r := range strings.SplitSeq(relax, ",") {
		if r = strings.TrimSpace(r); r != "" {
			relaxed[r] = true
		}
	}
	byName := map[string]*fileInfo{}
	for _, f := range files {
		name := filepath.Base(fset.Position(f.Package).Filename)
		if !testFiles[name] {
			continue
		}
		src, err := os.ReadFile(fset.Position(f.Package).Filename)
		if err != nil {
			return err
		}
		fi := &fileInfo{name: name, lines: bytes.Count(src, []byte("\n")), src: string(src), direct: true, helpers: map[string]bool{}}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Test") {
				fi.tests = append(fi.tests, fd.Name.Name)
			}
		}
		byName[name] = fi
	}
	for id, obj := range info.Uses {
		if obj == nil || obj.Pkg() != tpkg || !belongsToPackage(obj, tpkg) {
			continue
		}
		user := byName[filepath.Base(fset.Position(id.Pos()).Filename)]
		decl := filepath.Base(fset.Position(obj.Pos()).Filename)
		if user == nil || decl == user.name {
			continue
		}
		if testFiles[decl] {
			user.helpers[decl] = true
		} else if !obj.Exported() && !relaxed[obj.Name()] {
			user.direct = false
		}
	}
	for _, fi := range byName {
		fi.blackbox = fi.direct
	}
	for changed := true; changed; { // helper closure: a helper file that is white-box makes its users white-box
		changed = false
		for _, fi := range byName {
			for h := range fi.helpers {
				if fi.blackbox && !byName[h].blackbox {
					fi.blackbox, changed = false, true
				}
			}
		}
	}

	cited := ledgerTestNames(meta.Dir)
	sets := map[string][]*fileInfo{}
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		fi := byName[name]
		sets["in-package"] = append(sets["in-package"], fi)
		if !fi.blackbox {
			continue
		}
		sets["blackbox"] = append(sets["blackbox"], fi)
		if fi.excludeBy = excludeReason(fi, cited); fi.excludeBy == "" {
			sets["wave"] = append(sets["wave"], fi)
		}
	}
	label := ""
	if relax != "" {
		label = " (relax " + relax + ")"
	}
	_, _ = fmt.Fprintf(w, "%-12s %6s %8s %6s%s\n", "set", "files", "lines", "tests", label)
	for _, s := range []string{"in-package", "blackbox", "wave"} {
		lines, tests := 0, 0
		for _, fi := range sets[s] {
			lines += fi.lines
			tests += len(fi.tests)
		}
		_, _ = fmt.Fprintf(w, "%-12s %6d %8d %6d\n", s, len(sets[s]), lines, tests)
		if outDir != "" {
			var b strings.Builder
			for _, fi := range sets[s] {
				_, _ = fmt.Fprintf(&b, "%s\t%s\n", fi.name, fi.excludeBy)
			}
			if err := os.WriteFile(filepath.Join(outDir, s+".txt"), []byte(b.String()), 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// belongsToPackage: package-level objects, plus fields and methods (declared on
// the package's types).
func belongsToPackage(obj types.Object, pkg *types.Package) bool {
	if obj.Parent() == pkg.Scope() {
		return true
	}
	switch o := obj.(type) {
	case *types.Var:
		return o.IsField()
	case *types.Func:
		return o.Signature().Recv() != nil
	}
	return false
}

var excludeReasons = []struct {
	reason string
	re     *regexp.Regexp
}{
	{"fuzz", regexp.MustCompile(`(?m)^func Fuzz`)},
	{"testdata", regexp.MustCompile(`"testdata`)},
	{"postgres", regexp.MustCompile(`KEYORIX_TEST_PG_DSN|requirePostgres|pgtest\.|PostgresDSN`)},
	{"registry", regexp.MustCompile(`(?m)^func init\(\)`)},
	{"source-scan", regexp.MustCompile(`"go/parser"`)},
}

func excludeReason(fi *fileInfo, cited map[string]bool) string {
	if strings.Contains(fi.name, "postgres") {
		return "postgres"
	}
	for _, e := range excludeReasons {
		if e.re.MatchString(fi.src) {
			return e.reason
		}
	}
	for _, t := range fi.tests {
		if cited[t] {
			return "ledger:" + t
		}
	}
	return ""
}

// ledgerTestNames returns every Test* name that a ledger row or an INVARIANTS
// entry for the package mentions.
func ledgerTestNames(pkgDir string) map[string]bool {
	root := pkgDir
	for ; root != filepath.Dir(root); root = filepath.Dir(root) {
		if _, err := os.Stat(filepath.Join(root, "docs", "security-closures.d")); err == nil {
			break
		}
	}
	var paths []string
	for _, g := range []string{"docs/security-closures.d/*.tsv", "docs/adr-conformance-enforced.tsv", "docs/adr-conformance-enforced.d/*.tsv"} {
		m, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(g)))
		paths = append(paths, m...)
	}
	m, _ := filepath.Glob(filepath.Join(pkgDir, "INVARIANTS*.md"))
	paths = append(paths, m...)
	m, _ = filepath.Glob(filepath.Join(pkgDir, "INVARIANTS.d", "*.md"))
	paths = append(paths, m...)
	names := map[string]bool{}
	re := regexp.MustCompile(`\bTest[A-Za-z0-9_]+`)
	for _, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- repo ledger files found by glob
		if err != nil {
			continue
		}
		for _, n := range re.FindAllString(string(b), -1) {
			names[n] = true
		}
	}
	return names
}
