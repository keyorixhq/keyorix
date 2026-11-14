// Command testreach narrows a package's tests to the ones that can observe a
// changed NON-CODE input (MQ-TEST-SLIM-1, lever B; shadow mode first).
//
// scripts/ci/select-affected.py selects a whole package when one of its string
// literals names a changed file (rule 3) or a non-Go file sits in its directory
// (rule 2). Most of such a package's tests never read that file: over 60 merge
// queue rounds (10-13 Nov 2026) 43% of the selected leg-minutes came from
// packages that no changed Go code reached. testreach answers, per package,
// which top-level tests can reach the changed file. It never judges compiled
// code: select-affected calls it only for packages no changed Go code reaches.
//
// Input (stdin), a JSON list of requests:
//
//	{"dir": "server/http", "import_path": "github.com/keyorixhq/keyorix/server/http",
//	 "targets": [{"file": "web/e2e/real/x.spec.ts", "outside": true}],
//	 "test_files": ["a_test.go"],
//	 "seed_imports": ["github.com/keyorixhq/keyorix/internal/statemap"],
//	 "reader_imports": ["github.com/keyorixhq/keyorix/internal/testutil/srcpath"],
//	 "chain": [{"dir": "internal/statemap", "seed_imports": [], "is_seed": true}]}
//
//	dir            repo-relative package directory (testreach runs at the repo root)
//	targets        changed non-Go files, or .go files of OTHER packages, that rule
//	               2/3 matched; outside = select-affected's "outside every package"
//	test_files     changed _test.go files of this package (base names)
//	seed_imports   this package's imports that are, or depend on, a package whose
//	               non-test code names a target (a rule-3 CODE seed)
//	reader_imports this package's in-module imports that can read the source tree
//	               without a literal path (runtime.Caller, os.Getwd, go/parser,
//	               go/packages, os/exec, or an import of such a package)
//	chain          the packages linked into the test binary that are, or depend
//	               on, a code seed (non-test files only): their init functions and
//	               package-level initialisers run in every test
//
// Output (stdout): a JSON list of results, one per request: "all": true with a
// reason when the package cannot be narrowed, else the selected test names.
//
// How a test reaches something (an over-approximation on purpose):
//   - Every .go file in a directory is parsed, whatever its build constraints.
//   - A top-level declaration references every top-level declaration whose NAME
//     appears as an identifier in it (selectors included), and a type also
//     references every method declared on it. x.M() therefore reaches every M of
//     the package: interface calls, method values and promoted methods are
//     covered because names, not types, are matched.
//   - init functions, TestMain and package-level vars/consts whose initialiser
//     calls anything run in every test: if they reach a seed, ALL tests are
//     selected. The same holds for those of every chain package. A var whose
//     initialiser is plain data (literals, composite literals) is reached
//     through the declarations that use it, like any other declaration.
//   - A declaration is a seed when it is declared in a changed test file; when
//     it uses a seed_imports package; when a string literal in it names a target
//     (rule 3's semantics: the basename of a non-Go target, the target's path or
//     a directory above it, a one-word directory only for an outside target);
//     for a target inside dir also when a literal names it relative to dir, is
//     ".", "./", "" or a glob, or when it calls a file-reading function
//     (os.ReadDir/ReadFile/Open/Stat, filepath.Walk/Glob, fs.WalkDir, ...) or uses
//     a reader_imports package; and Fuzz<Name> when a target is under
//     testdata/fuzz/<Name>/ (go test reads that corpus itself).
//   - Falls back to ALL tests on a parse error, a dot import, //go:linkname, or
//     a //go:embed in a test file.
//
// Not covered (exactly as for select-affected's rule 3): a test that reaches a
// file only through a path that another package builds at run time from pieces
// none of whose literals names it. The sampled full runs and the nightly full
// run on main cover that.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type target struct {
	File    string `json:"file"`
	Outside bool   `json:"outside"`
}

type chainPkg struct {
	Dir         string   `json:"dir"`
	SeedImports []string `json:"seed_imports"`
	IsSeed      bool     `json:"is_seed"`
}

type request struct {
	Dir           string     `json:"dir"`
	ImportPath    string     `json:"import_path"`
	Targets       []target   `json:"targets"`
	TestFiles     []string   `json:"test_files"`
	SeedImports   []string   `json:"seed_imports"`
	ReaderImports []string   `json:"reader_imports"`
	Chain         []chainPkg `json:"chain"`
}

type result struct {
	ImportPath string   `json:"import_path"`
	All        bool     `json:"all"`
	Reason     string   `json:"reason"`
	Tests      []string `json:"tests"`
	Total      int      `json:"total"`
}

// fileAccess: calls that can read files of a directory without a literal
// naming them, by import path of the qualifier.
var fileAccess = map[string][]string{
	"os":                             {"ReadDir", "ReadFile", "Open", "OpenFile", "Stat", "Lstat", "DirFS", "OpenRoot", "OpenInRoot", "CopyFS", "Getwd"},
	"io/ioutil":                      {"ReadDir", "ReadFile"},
	"io/fs":                          {"WalkDir", "Glob", "ReadDir", "ReadFile", "Sub", "Stat"},
	"path/filepath":                  {"Walk", "WalkDir", "Glob"},
	"go/parser":                      {"ParseDir", "ParseFile"},
	"golang.org/x/tools/go/packages": {"Load"},
	"os/exec":                        {"Command", "CommandContext"},
	"runtime":                        {"Caller", "Callers"},
}

type decl struct {
	name     string // function, method or spec name
	recv     string // receiver type name, for a method
	file     string
	global   bool   // init, TestMain, initialised package-level var/const
	test     string // Test*/Fuzz*/Example* function name, or ""
	idents   map[string]bool
	literals []string
	imports  map[string]bool // import paths used through a qualifier
	access   bool            // calls a fileAccess function
}

func main() {
	var reqs []request
	if err := json.NewDecoder(os.Stdin).Decode(&reqs); err != nil {
		fmt.Fprintln(os.Stderr, "testreach: bad request:", err)
		os.Exit(2)
	}
	out := make([]result, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, analyse(r))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		os.Exit(2)
	}
}

func analyse(r request) result {
	every := func(reason string, total int) result {
		return result{ImportPath: r.ImportPath, All: true, Reason: reason, Total: total}
	}
	decls, why := parseDir(r.Dir, true)
	if why != "" {
		return every(why, 0)
	}
	var tests []string
	for _, d := range decls {
		if d.test != "" {
			tests = append(tests, d.test)
		}
	}
	tests = uniq(tests)
	if len(tests) == 0 {
		return result{ImportPath: r.ImportPath, Reason: "no Test/Fuzz/Example functions", Tests: []string{}}
	}
	for _, c := range r.Chain {
		if w := chainInitReaches(c, r.Targets); w != "" {
			return every(w, len(tests))
		}
	}

	changedTest := set(r.TestFiles)
	seedImp, readerImp := set(r.SeedImports), set(r.ReaderImports)
	seeds := map[int]string{}
	for i, d := range decls {
		if w := seedReason(d, r, changedTest, seedImp, readerImp); w != "" {
			seeds[i] = w
		}
	}
	for _, t := range r.Targets {
		if name, ok := fuzzCorpusOwner(t.File, r.Dir); ok {
			for i, d := range decls {
				if d.test == name {
					seeds[i] = "fuzz corpus " + t.File
				}
			}
		}
	}
	reach := reachSeeds(decls, seeds)
	sel := []string{}
	for i, d := range decls {
		w, ok := reach[i]
		if !ok {
			continue
		}
		if d.global {
			return every(fmt.Sprintf("%s runs in every test and reaches a changed input (%s)", d.name, w), len(tests))
		}
		if d.test != "" {
			sel = append(sel, d.test)
		}
	}
	sel = uniq(sel)
	return result{ImportPath: r.ImportPath, Reason: fmt.Sprintf("%d of %d tests reach a changed input", len(sel), len(tests)), Tests: sel, Total: len(tests)}
}

func seedReason(d *decl, r request, changedTest, seedImp, readerImp map[string]bool) string {
	if changedTest[d.file] {
		return "declared in changed " + d.file
	}
	for imp := range d.imports {
		if seedImp[imp] {
			return "uses " + imp
		}
	}
	for _, t := range r.Targets {
		inDir := strings.HasPrefix(t.File, r.Dir+"/")
		if inDir && d.access {
			return "reads files of " + r.Dir
		}
		if inDir {
			for imp := range d.imports {
				if readerImp[imp] {
					return "uses " + imp + ", which can read the source tree"
				}
			}
		}
		if w := literalNames(d, t, r.Dir, inDir); w != "" {
			return w
		}
	}
	return ""
}

// chainInitReaches: the reason a chain package's init or package-level
// initialisers can observe a target, or "".
func chainInitReaches(c chainPkg, targets []target) string {
	decls, why := parseDir(c.Dir, false)
	if why != "" {
		return c.Dir + ": " + why
	}
	seedImp := set(c.SeedImports)
	seeds := map[int]string{}
	for i, d := range decls {
		for imp := range d.imports {
			if seedImp[imp] {
				seeds[i] = "uses " + imp
			}
		}
		if c.IsSeed {
			for _, t := range targets {
				if w := literalNames(d, t, c.Dir, false); w != "" {
					seeds[i] = w
				}
			}
		}
	}
	for i, w := range reachSeeds(decls, seeds) {
		if decls[i].global {
			return fmt.Sprintf("%s: %s runs in every test binary that links it and reaches a changed input (%s)", c.Dir, decls[i].name, w)
		}
	}
	return ""
}

// reachSeeds: every declaration that reaches a seed, with the seed's reason.
func reachSeeds(decls []*decl, seeds map[int]string) map[int]string {
	byName, methods := map[string][]int{}, map[string][]int{}
	for i, d := range decls {
		byName[d.name] = append(byName[d.name], i)
		if d.recv != "" {
			methods[d.recv] = append(methods[d.recv], i)
		}
	}
	users := make([][]int, len(decls)) // users[j]: declarations referencing j
	for i, d := range decls {
		for id := range d.idents {
			for _, j := range byName[id] {
				users[j] = append(users[j], i)
				for _, m := range methods[decls[j].name] {
					users[m] = append(users[m], i)
				}
			}
		}
	}
	reach := map[int]string{}
	var queue []int
	for i, w := range seeds {
		reach[i] = w
		queue = append(queue, i)
	}
	for len(queue) > 0 {
		j := queue[0]
		queue = queue[1:]
		for _, i := range users[j] {
			if _, seen := reach[i]; !seen {
				reach[i] = reach[j]
				queue = append(queue, i)
			}
		}
	}
	return reach
}

// parseDir: the top-level declarations of every .go file in dir (test files
// only when withTests). A non-empty string: the package cannot be narrowed.
func parseDir(dir string, withTests bool) ([]*decl, string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "cannot read " + dir + ": " + err.Error()
	}
	fset := token.NewFileSet()
	var decls []*decl
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || (!withTests && strings.HasSuffix(n, "_test.go")) {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.ParseComments)
		if err != nil {
			return nil, "parse error: " + err.Error()
		}
		ds, why := fileDecls(n, f)
		if why != "" {
			return nil, why
		}
		decls = append(decls, ds...)
	}
	return decls, ""
}

func fileDecls(name string, f *ast.File) ([]*decl, string) {
	isTestFile := strings.HasSuffix(name, "_test.go")
	imports := map[string]string{} // local name -> import path
	for _, is := range f.Imports {
		p, _ := strconv.Unquote(is.Path.Value)
		local := path.Base(p)
		if is.Name != nil {
			local = is.Name.Name
		}
		if local == "." {
			return nil, name + ": dot import of " + p
		}
		imports[local] = p
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname") {
				return nil, name + ": //go:linkname"
			}
			if isTestFile && strings.HasPrefix(c.Text, "//go:embed") {
				return nil, name + ": //go:embed in a test file"
			}
		}
	}
	var out []*decl
	add := func(n string, node ast.Node, global bool) *decl {
		x := &decl{name: n, file: name, global: global, idents: map[string]bool{}, imports: map[string]bool{}}
		scan(x, node, imports)
		out = append(out, x)
		return x
	}
	for _, dd := range f.Decls {
		switch d := dd.(type) {
		case *ast.FuncDecl:
			top := d.Recv == nil
			x := add(d.Name.Name, d, top && (d.Name.Name == "init" || d.Name.Name == "TestMain"))
			if !top && len(d.Recv.List) > 0 {
				x.recv = recvName(d.Recv.List[0].Type)
			}
			if top && isTestFile && isTestName(d.Name.Name) {
				x.test = d.Name.Name
			}
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				continue
			}
			for _, s := range d.Specs {
				switch sp := s.(type) {
				case *ast.ValueSpec:
					// An initialiser runs before every test only as far as it
					// calls something; a literal or composite value is data,
					// reached through the declarations that use it.
					calls := hasCall(sp)
					for _, n := range sp.Names {
						add(n.Name, sp, calls)
					}
				case *ast.TypeSpec:
					add(sp.Name.Name, sp, false)
				}
			}
		}
	}
	return out, ""
}

// hasCall: the value spec's initialisers contain a call (or a conversion,
// which looks the same), anywhere, function literals included.
func hasCall(sp *ast.ValueSpec) bool {
	found := false
	for _, v := range sp.Values {
		ast.Inspect(v, func(n ast.Node) bool {
			if _, ok := n.(*ast.CallExpr); ok {
				found = true
			}
			return !found
		})
	}
	return found
}

func scan(x *decl, n ast.Node, imports map[string]string) {
	ast.Inspect(n, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.Ident:
			x.idents[v.Name] = true
		case *ast.BasicLit:
			if v.Kind == token.STRING && len(v.Value) >= 2 {
				x.literals = append(x.literals, v.Value[1:len(v.Value)-1])
			}
		case *ast.SelectorExpr:
			if id, ok := v.X.(*ast.Ident); ok {
				if p, ok := imports[id.Name]; ok {
					x.imports[p] = true
					if slices.Contains(fileAccess[p], v.Sel.Name) {
						x.access = true
					}
				}
			}
		}
		return true
	})
}

func recvName(e ast.Expr) string {
	for {
		switch t := e.(type) {
		case *ast.StarExpr:
			e = t.X
		case *ast.IndexExpr:
			e = t.X
		case *ast.IndexListExpr:
			e = t.X
		case *ast.Ident:
			return t.Name
		default:
			return ""
		}
	}
}

// isTestName follows `go test`: Test, Fuzz or Example, then nothing or a
// character that is not a lower-case letter.
func isTestName(n string) bool {
	for _, p := range []string{"Test", "Fuzz", "Example"} {
		if rest, ok := strings.CutPrefix(n, p); ok && (rest == "" || rest[0] < 'a' || rest[0] > 'z') {
			return true
		}
	}
	return false
}

// literalNames: why a string literal of d names target t, or "".
func literalNames(d *decl, t target, dir string, inDir bool) string {
	base := path.Base(t.File)
	for _, lit := range d.literals {
		if inDir && (lit == "." || lit == "./" || lit == "" || strings.ContainsAny(lit, "*?[")) {
			return fmt.Sprintf("literal %q may name files of %s", lit, dir)
		}
		if len(lit) > 300 || strings.Contains(lit, `\n`) {
			continue
		}
		parts := normalize(lit)
		if len(parts) == 0 {
			continue
		}
		if !strings.HasSuffix(t.File, ".go") && slices.Contains(parts, base) {
			return fmt.Sprintf("literal %q names %s", lit, t.File)
		}
		if strings.ContainsAny(parts[len(parts)-1], "*?[") {
			parts = parts[:len(parts)-1]
		}
		p := strings.Join(parts, "/")
		if p == "" {
			continue
		}
		for a := t.File; a != "." && a != "/" && a != ""; a = path.Dir(a) {
			if p == a && (t.Outside || strings.Contains(p, "/")) {
				return fmt.Sprintf("literal %q names %s", lit, t.File)
			}
			if rel, ok := strings.CutPrefix(a, dir+"/"); inDir && ok && p == rel {
				return fmt.Sprintf("literal %q names %s relative to %s", lit, t.File, dir)
			}
		}
	}
	return ""
}

// normalize mirrors select-affected.py's normalize(): drop "", ".", ".." and a
// leading format verb or template component.
func normalize(lit string) []string {
	var parts []string
	for p := range strings.SplitSeq(strings.ReplaceAll(lit, `\`, "/"), "/") {
		if p != "" && p != "." && p != ".." {
			parts = append(parts, p)
		}
	}
	for len(parts) > 0 && strings.ContainsAny(parts[0], "%${") {
		parts = parts[1:]
	}
	return parts
}

func fuzzCorpusOwner(file, dir string) (string, bool) {
	rest, ok := strings.CutPrefix(file, dir+"/testdata/fuzz/")
	if !ok {
		return "", false
	}
	name, _, _ := strings.Cut(rest, "/")
	return name, name != ""
}

func set(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, x := range s {
		m[x] = true
	}
	return m
}

func uniq(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}
