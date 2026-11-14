// scan.go — walk the root module, parse every .go file with go/parser, and
// build: the sink list, a name-keyed function index, a conservative
// name-based static call graph, and the set of Fuzz targets.
//
// Nested modules (any directory other than the root that contains its own
// go.mod) are NOT descended into — they are separate modules and out of
// scope for "the root module".
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Sink is one dangerous call site plus its classification.
type Sink struct {
	Kind         SinkKind
	File         string // module-relative
	Line         int
	Func         string // enclosing-function display key
	Pkg          string // module-relative package dir
	Detail       string
	APIReachable bool
	APIEntry     string // the entry root a path was found from (for the report)
	FuzzCovered  bool
	FuzzBy       string // the Fuzz target that reaches it (for the report)
	Product      bool   // false for dev tooling under scripts/ or tools/
}

// fnDecl is one function/method declaration.
type fnDecl struct {
	Pkg     string // module-relative dir
	Name    string // simple name (method or func name)
	Recv    string // receiver type name, "" for plain funcs
	Display string // Pkg + "." + (recv?) + Name
	IsFuzz  bool
	IsTest  bool     // declared in a _test.go file
	Calls   []string // simple callee names (method-call fallback, over-approx)
	QCalls  []string // package-qualified callees "pkgRel\x00name" (precise)
}

// scanResult is everything one pass over the tree produced.
type scanResult struct {
	Sinks     []Sink
	Funcs     []*fnDecl
	byName    map[string][]*fnDecl // simple name -> decls (methods + funcs)
	byDisp    map[string]*fnDecl
	byPkgFunc map[string]*fnDecl // "pkgRel\x00name" -> package-level func decl
	modPath   string             // module path from go.mod
	skipped   []string           // nested-module dirs skipped
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "testdata": false,
	"dist": true, "build": true, ".next": true, "coverage": true,
}

const maxFileSize = 4 << 20

// scanModule walks root, treating root itself as the module and skipping any
// subtree rooted at a nested go.mod. When includeTestdata is false the
// tool's own testdata fixtures are excluded (the real run); the test passes
// true to analyse the fixture.
func scanModule(root string, includeTestdata bool) (*scanResult, error) {
	res := &scanResult{byName: map[string][]*fnDecl{}, byDisp: map[string]*fnDecl{}, byPkgFunc: map[string]*fnDecl{}}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	res.modPath = readModulePath(filepath.Join(rootAbs, "go.mod"))
	fset := token.NewFileSet()

	err = filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != rootAbs && skipDirs[name] {
				return fs.SkipDir
			}
			if !includeTestdata && name == "testdata" {
				return fs.SkipDir
			}
			// Skip nested modules (a go.mod anywhere but the root).
			if path != rootAbs {
				if _, e := os.Stat(filepath.Join(path, "go.mod")); e == nil {
					rel, _ := filepath.Rel(rootAbs, path)
					res.skipped = append(res.skipped, rel)
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() > maxFileSize {
			return nil
		}
		rel, _ := filepath.Rel(rootAbs, path)
		return scanFile(fset, rootAbs, path, rel, res)
	})
	if err != nil {
		return nil, err
	}

	for _, f := range res.Funcs {
		res.byName[f.Name] = append(res.byName[f.Name], f)
		res.byDisp[f.Display] = f
		if f.Recv == "" {
			res.byPkgFunc[f.Pkg+"\x00"+f.Name] = f
		}
	}
	sort.Slice(res.Sinks, func(i, j int) bool {
		a, b := res.Sinks[i], res.Sinks[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return res, nil
}

func scanFile(fset *token.FileSet, rootAbs, path, rel string, res *scanResult) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil // unreadable file: skip, never fail the whole walk
	}
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil // unparseable (e.g. build-tag fragment): skip
	}
	isTest := strings.HasSuffix(rel, "_test.go")
	pkgRel := filepath.ToSlash(filepath.Dir(rel))

	imports := importMap(file)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		recv := recvTypeName(fn)
		display := pkgRel + "." + fn.Name.Name
		if recv != "" {
			display = pkgRel + ".(" + recv + ")." + fn.Name.Name
		}
		calls, qcalls := collectCalls(fn, pkgRel, imports, res.modPath)
		fd := &fnDecl{
			Pkg: pkgRel, Name: fn.Name.Name, Recv: recv, Display: display,
			IsTest: isTest,
			IsFuzz: isTest && strings.HasPrefix(fn.Name.Name, "Fuzz") && hasTestingFParam(fn),
			Calls:  calls, QCalls: qcalls,
		}
		res.Funcs = append(res.Funcs, fd)

		// Sinks are listed from product code only (never _test.go): fuzz
		// harnesses and unit tests legitimately contain sink-shaped calls.
		if !isTest {
			matchSinks(fset, pkgRel, display, fn, imports, &res.Sinks)
		}
	}
	// Normalise sink file paths to module-relative.
	for i := range res.Sinks {
		if filepath.IsAbs(res.Sinks[i].File) {
			if r, e := filepath.Rel(rootAbs, res.Sinks[i].File); e == nil {
				res.Sinks[i].File = filepath.ToSlash(r)
			}
		}
	}
	return nil
}

// importMap maps a file's import local names to import paths.
func importMap(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		name := lastElem(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		m[name] = p
	}
	return m
}

func recvTypeName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	return exprTypeName(fn.Recv.List[0].Type)
}

func exprTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return exprTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr: // qualified type, e.g. testing.F -> "F"
		return t.Sel.Name
	case *ast.IndexExpr: // generic receiver Foo[T]
		return exprTypeName(t.X)
	case *ast.IndexListExpr:
		return exprTypeName(t.X)
	}
	return ""
}

func hasTestingFParam(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return false
	}
	return exprTypeName(fn.Type.Params.List[0].Type) == "F"
}

// collectCalls returns the call-graph edges out of this function, split into:
//
//   - qcalls: package-qualified, precisely resolvable edges "pkgRel\x00name".
//     A bare `Foo(...)` resolves to this package; an `imp.Foo(...)` where imp
//     is an import of THIS module resolves to that package. These are exact.
//   - calls: simple names for method calls on a value/receiver whose type is
//     not resolvable without go/types (the unavoidable over-approx edges).
//
// A call into stdlib or a dependency (e.g. fmt.Sprintf) resolves to no
// in-module target and is recorded as neither.
func collectCalls(fn *ast.FuncDecl, pkgRel string, imports map[string]string, modPath string) (calls, qcalls []string) {
	if fn.Body == nil {
		return nil, nil
	}
	seenC, seenQ := map[string]bool{}, map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := c.Fun.(type) {
		case *ast.Ident:
			// Bare call: same-package function (or dot-import/builtin).
			seenQ[pkgRel+"\x00"+f.Name] = true
		case *ast.SelectorExpr:
			if id, ok := f.X.(*ast.Ident); ok {
				if imp, isImport := imports[id.Name]; isImport {
					if rel, in := inModulePkg(imp, modPath); in {
						seenQ[rel+"\x00"+f.Sel.Name] = true
					}
					// else: stdlib/dependency call — no in-module target.
					return true
				}
			}
			// Method call on a value/receiver: type unknown without types.
			seenC[f.Sel.Name] = true
		}
		return true
	})
	return sortedKeys(seenC), sortedKeys(seenQ)
}

// inModulePkg maps an import path to this module's relative package dir when
// the import belongs to the module; otherwise in=false.
func inModulePkg(imp, modPath string) (rel string, in bool) {
	if modPath == "" {
		return "", false
	}
	if imp == modPath {
		return ".", true
	}
	if rest, ok := strings.CutPrefix(imp, modPath+"/"); ok {
		return rest, true
	}
	return "", false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readModulePath returns the module path declared in a go.mod file, or "".
func readModulePath(gomod string) string {
	data, err := os.ReadFile(gomod)
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
