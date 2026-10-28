// Command declrefs is the go/ast half of scripts/ci/coverage-shadow.py (lever C
// in shadow mode, CI-SELECT-2). A coverage profile only has blocks for
// executable statements, so a changed function signature, const, type or
// package-level var has no block of its own and the shadow cannot say whether
// it ran. This tool answers two questions about such lines, syntactically:
//
//   - which top-level declaration owns a changed line (a function header, or a
//     const/type/var spec, with the names it declares), and
//   - where else in the repository those names are referenced.
//
// It reads a JSON request on stdin and writes a JSON answer on stdout. It never
// writes a file and never runs go. Reference matching is deliberately an
// over-approximation (a field or method with the same name counts as a
// reference): a false "referenced" only keeps a test, a false "unreferenced"
// would skip one.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type request struct {
	Root   string           `json:"root"`
	Module string           `json:"module"`
	Files  map[string][]int `json:"files"` // repo-relative path -> changed new-side lines
}

// LineInfo describes what owns one changed line.
type LineInfo struct {
	Kind string `json:"kind"` // funcheader | decl | other
	// funcheader: first and last line of the body ({ ... }).
	Body []int `json:"body,omitempty"`
	// decl: the names declared by the spec(s) on the line (blank names are
	// left out), the declaring file, and whether evaluating the spec can run
	// code at init time (a var with a call other than errors.New).
	Names  []string `json:"names,omitempty"`
	Impure bool     `json:"impure,omitempty"`
}

// Site is one place a declared name is mentioned.
type Site struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Test bool   `json:"test"`
}

type response struct {
	Lines map[string]map[string]LineInfo `json:"lines"`
	// Refs is keyed "declaring file#Name".
	Refs map[string][]Site `json:"refs"`
	// ParseErrors lists files (requested or scanned) that did not parse. A
	// requested file that failed to parse has no Lines entry, so its lines
	// stay undetermined.
	ParseErrors []string `json:"parse_errors,omitempty"`
}

type declInfo struct {
	file    string
	pkgDir  string
	pkgName string
	name    string
	from    token.Position // start of the declaring spec
	to      token.Position // end of the declaring spec
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, ".scratch": true, "web": true, "testdata": true, "vendor": true, ".claude": true}

// maxRequestBytes caps the stdin request; it is a map of changed files to line numbers, far below this.
const maxRequestBytes = 16 << 20

func main() {
	var req request
	if err := json.NewDecoder(io.LimitReader(os.Stdin, maxRequestBytes)).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "declrefs: bad request:", err)
		os.Exit(2)
	}
	resp, err := run(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "declrefs:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fmt.Fprintln(os.Stderr, "declrefs:", err)
		os.Exit(1)
	}
}

func run(req request) (*response, error) {
	resp := &response{Lines: map[string]map[string]LineInfo{}, Refs: map[string][]Site{}}
	var decls []declInfo
	files := make([]string, 0, len(req.Files))
	for f := range req.Files {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, rel := range files {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, filepath.Join(req.Root, rel), nil, parser.SkipObjectResolution)
		if err != nil {
			resp.ParseErrors = append(resp.ParseErrors, rel)
			continue
		}
		infos, ds := classify(fset, af, rel, req.Files[rel])
		resp.Lines[rel] = infos
		decls = append(decls, ds...)
	}
	if len(decls) == 0 {
		return resp, nil
	}
	if err := scan(req, decls, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// classify maps each requested line of one file to its owner.
func classify(fset *token.FileSet, af *ast.File, rel string, lines []int) (map[string]LineInfo, []declInfo) {
	out := map[string]LineInfo{}
	var decls []declInfo
	seen := map[string]bool{}
	line := func(p token.Pos) int { return fset.Position(p).Line }
	for _, ln := range lines {
		info := LineInfo{Kind: "other"}
		for _, d := range af.Decls {
			if ln < line(d.Pos()) || ln > line(d.End()) {
				continue
			}
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Body != nil && ln <= line(d.Body.Lbrace) {
					info = LineInfo{Kind: "funcheader", Body: []int{line(d.Body.Lbrace), line(d.Body.Rbrace)}}
				}
			case *ast.GenDecl:
				if d.Tok == token.IMPORT {
					break
				}
				var names []string
				impure := false
				for _, s := range specsOn(fset, d, ln) {
					ns, imp := specNames(s, d.Tok)
					impure = impure || imp
					for _, n := range ns {
						names = append(names, n.Name)
						if !seen[n.Name] {
							seen[n.Name] = true
							decls = append(decls, declInfo{file: rel, name: n.Name, from: fset.Position(s.Pos()), to: fset.Position(s.End()), pkgName: af.Name.Name})
						}
					}
				}
				info = LineInfo{Kind: "decl", Names: dedupe(names), Impure: impure}
			}
		}
		out[strconv.Itoa(ln)] = info
	}
	return out, decls
}

// specsOn returns the specs of a const/type/var declaration that a changed
// line belongs to. A line inside no spec (the `const (` or `)` line) and any
// line of a group whose specs depend on one another (iota or an implicit
// repetition: adding a spec renumbers the later ones) belongs to ALL specs.
func specsOn(fset *token.FileSet, d *ast.GenDecl, ln int) []ast.Spec {
	if d.Tok == token.CONST && constGroupLinked(d) {
		return d.Specs
	}
	var hit []ast.Spec
	for _, s := range d.Specs {
		if ln >= fset.Position(s.Pos()).Line && ln <= fset.Position(s.End()).Line {
			hit = append(hit, s)
		}
	}
	if len(hit) == 0 {
		return d.Specs
	}
	return hit
}

func constGroupLinked(d *ast.GenDecl) bool {
	linked := false
	for _, s := range d.Specs {
		vs, ok := s.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if len(vs.Values) == 0 {
			linked = true
		}
		for _, v := range vs.Values {
			ast.Inspect(v, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == "iota" {
					linked = true
				}
				return true
			})
		}
	}
	return linked
}

// specNames: the non-blank names a spec declares, and whether it can run code
// when the package initialises.
func specNames(s ast.Spec, tok token.Token) ([]*ast.Ident, bool) {
	switch s := s.(type) {
	case *ast.TypeSpec:
		return []*ast.Ident{s.Name}, false
	case *ast.ValueSpec:
		var ns []*ast.Ident
		for _, n := range s.Names {
			if n.Name != "_" {
				ns = append(ns, n)
			}
		}
		impure := false
		if tok == token.VAR {
			for _, v := range s.Values {
				if !pureInit(v) {
					impure = true
				}
			}
			if len(s.Names) == 1 && s.Names[0].Name == "_" && len(s.Values) > 0 {
				impure = true // `var _ = f()` exists for its effect
			}
		}
		return ns, impure
	}
	return nil, true
}

// pureInit: an initialiser whose evaluation cannot run repository code or
// panic: literals, identifiers, operators and errors.New.
func pureInit(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit, *ast.Ident:
		return true
	case *ast.ParenExpr:
		return pureInit(e.X)
	case *ast.UnaryExpr:
		return e.Op != token.ARROW && pureInit(e.X)
	case *ast.BinaryExpr:
		return e.Op != token.QUO && e.Op != token.REM && pureInit(e.X) && pureInit(e.Y) // a zero divisor panics
	case *ast.SelectorExpr:
		_, ok := e.X.(*ast.Ident)
		return ok
	case *ast.CompositeLit:
		for _, el := range e.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if !pureInit(kv.Key) || !pureInit(kv.Value) {
					return false
				}
			} else if !pureInit(el) {
				return false
			}
		}
		return true
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "errors" || sel.Sel.Name != "New" {
			return false
		}
		for _, a := range e.Args {
			if !pureInit(a) {
				return false
			}
		}
		return true
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// scan walks every Go file of the repository (all modules) once and records
// the mentions of each declared name.
func scan(req request, decls []declInfo, resp *response) error {
	byPkg := map[string][]*declInfo{} // package dir -> declarations in it
	for i := range decls {
		decls[i].pkgDir = path.Dir(decls[i].file)
		byPkg[decls[i].pkgDir] = append(byPkg[decls[i].pkgDir], &decls[i])
	}
	record := func(d *declInfo, file string, pos token.Position, test bool) {
		if file == d.file && pos.Line >= d.from.Line && pos.Line <= d.to.Line {
			return // the declaring spec itself (a recursive type, the name)
		}
		key := d.file + "#" + d.name
		resp.Refs[key] = append(resp.Refs[key], Site{File: file, Line: pos.Line, Test: test})
	}
	// make sure every declared name has an entry, so "no references" is explicit
	for _, d := range decls {
		resp.Refs[d.file+"#"+d.name] = []Site{}
	}
	return filepath.WalkDir(req.Root, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if de.IsDir() {
			if skipDirs[de.Name()] && p != req.Root {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, err := filepath.Rel(req.Root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			resp.ParseErrors = append(resp.ParseErrors, rel)
			return nil
		}
		test := strings.HasSuffix(rel, "_test.go")
		dir := path.Dir(rel)
		// same package: the directory of a declaring file, package clause
		// equal (an external _test package imports the package instead)
		for pkgDir, ds := range byPkg {
			if dir == pkgDir && af.Name.Name == ds[0].pkgName {
				for _, d := range ds {
					ast.Inspect(af, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok && id.Name == d.name {
							record(d, rel, fset.Position(id.Pos()), test)
						}
						return true
					})
				}
				continue
			}
			ip := req.Module + "/" + pkgDir
			alias, dot := importAlias(af, ip, ds[0].pkgName)
			if alias == "" && !dot {
				continue
			}
			for _, d := range ds {
				ast.Inspect(af, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.SelectorExpr:
						if x, ok := n.X.(*ast.Ident); ok && !dot && x.Name == alias && n.Sel.Name == d.name {
							record(d, rel, fset.Position(n.Sel.Pos()), test)
						}
					case *ast.Ident:
						if dot && n.Name == d.name {
							record(d, rel, fset.Position(n.Pos()), test)
						}
					}
					return true
				})
			}
		}
		return nil
	})
}

// importAlias: the name under which af imports importPath ("" if it does not;
// dot=true for a dot import).
func importAlias(af *ast.File, importPath, pkgName string) (alias string, dot bool) {
	for _, im := range af.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		switch {
		case im.Name == nil:
			return pkgName, false
		case im.Name.Name == ".":
			return "", true
		case im.Name.Name == "_":
			return "", false
		default:
			return im.Name.Name, false
		}
	}
	return "", false
}
