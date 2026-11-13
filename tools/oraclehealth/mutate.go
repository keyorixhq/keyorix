package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Mutation is a single planted source change: a byte span [Start,End) in File
// replaced by New (originally Orig). It is applied by rewriting File's content
// with the span swapped, and reverted by writing the original content back.
type Mutation struct {
	File string `json:"file"` // path relative to the module root
	Abs  string `json:"-"`    // absolute path in the working copy
	Line int    `json:"line"`
	Func string `json:"func"`
	Op   string `json:"op"`   // mutation-operator name
	Orig string `json:"orig"` // original source fragment
	New  string `json:"new"`  // replacement source fragment
	// byte offsets within the file; not serialised
	Start int `json:"-"`
	End   int `json:"-"`
}

func (m Mutation) String() string {
	return fmt.Sprintf("%s:%d %s [%s] %q -> %q", m.File, m.Line, m.Func, m.Op, m.Orig, m.New)
}

// collectMutations parses every non-test, non-generated .go file directly inside
// pkgDir (absolute path inside the working copy) and returns the full, ordered
// set of candidate mutations. root is the module root (for relative paths);
// funcAllow, when non-empty, restricts mutations to those enclosing functions.
func collectMutations(root, pkgDir string, funcAllow map[string]bool) ([]Mutation, error) {
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return nil, err
	}
	var muts []Mutation
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		abs := filepath.Join(pkgDir, e.Name())
		fm, err := collectFile(root, abs, funcAllow)
		if err != nil {
			return nil, err
		}
		muts = append(muts, fm...)
	}
	sort.Slice(muts, func(i, j int) bool {
		if muts[i].File != muts[j].File {
			return muts[i].File < muts[j].File
		}
		if muts[i].Start != muts[j].Start {
			return muts[i].Start < muts[j].Start
		}
		return muts[i].Op < muts[j].Op
	})
	return muts, nil
}

func collectFile(root, abs string, funcAllow map[string]bool) ([]Mutation, error) {
	src, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	if isGenerated(src) {
		return nil, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, abs, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, nil // unparseable files are silently skipped, not fatal
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		rel = abs
	}

	off := func(p token.Pos) int { return fset.Position(p).Offset }
	frag := func(a, b token.Pos) string { return string(src[off(a):off(b)]) }
	lineOf := func(p token.Pos) int { return fset.Position(p).Line }

	var muts []Mutation
	add := func(startP, endP token.Pos, fn, op, newText string) {
		s, e := off(startP), off(endP)
		if s < 0 || e > len(src) || s >= e {
			return
		}
		muts = append(muts, Mutation{
			File: rel, Abs: abs, Line: lineOf(startP), Func: fn,
			Op: op, Orig: string(src[s:e]), New: newText, Start: s, End: e,
		})
	}

	// Track the enclosing function and whether it returns an error, so the
	// "drop error guard" operator only fires where a dropped return actually
	// removes an error signal.
	type fnCtx struct {
		name        string
		returnsErr  bool
		start, stop token.Pos
	}
	var fns []fnCtx
	ast.Inspect(file, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok && fd.Body != nil {
			fns = append(fns, fnCtx{name: fd.Name.Name, returnsErr: resultsHaveError(fd.Type), start: fd.Pos(), stop: fd.End()})
		}
		return true
	})
	enclosing := func(p token.Pos) (string, bool) {
		name, retErr := "", false
		for _, f := range fns {
			if p >= f.start && p < f.stop {
				name, retErr = f.name, f.returnsErr // innermost wins (fns appended in order; keep last match)
			}
		}
		return name, retErr
	}
	allowed := func(fn string) bool { return len(funcAllow) == 0 || funcAllow[fn] }

	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			fn, _ := enclosing(x.OpPos)
			if !allowed(fn) {
				return true
			}
			opStart := x.OpPos
			opStr := x.Op.String()
			opEnd := token.Pos(int(x.OpPos) + len(opStr))
			if nw, name, ok := flipBinaryOp(x.Op); ok {
				add(opStart, opEnd, fn, name, nw)
			}
		case *ast.IfStmt:
			fn, retErr := enclosing(x.Pos())
			if !allowed(fn) {
				return true
			}
			// Negate the whole condition.
			add(x.Cond.Pos(), x.Cond.End(), fn, "negate-cond", "!("+frag(x.Cond.Pos(), x.Cond.End())+")")
			// Drop an if-guard whose body returns (early-exit / error guard).
			if retErr && bodyReturns(x.Body) && x.Else == nil {
				add(x.Pos(), x.End(), fn, "drop-error-guard", "{}")
			}
		case *ast.BasicLit:
			if x.Kind != token.INT {
				return true
			}
			fn, _ := enclosing(x.Pos())
			if !allowed(fn) {
				return true
			}
			for _, nw := range bumpInt(x.Value) {
				add(x.Pos(), x.End(), fn, "bound-const", nw)
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, _ := sel.X.(*ast.Ident)
			if pkg == nil {
				return true
			}
			fn, _ := enclosing(x.Pos())
			if !allowed(fn) {
				return true
			}
			if repl, ok := neuterEqualityCall(pkg.Name, sel.Sel.Name); ok {
				add(x.Pos(), x.End(), fn, "skip-constant-compare", repl)
			}
		}
		return true
	})
	return muts, nil
}

// flipBinaryOp returns the mutated operator text, an operator name and ok for
// the comparison / logical operators we mutate.
func flipBinaryOp(op token.Token) (string, string, bool) {
	switch op {
	case token.LSS:
		return "<=", "cmp-lt-to-le", true
	case token.LEQ:
		return "<", "cmp-le-to-lt", true
	case token.GTR:
		return ">=", "cmp-gt-to-ge", true
	case token.GEQ:
		return ">", "cmp-ge-to-gt", true
	case token.EQL:
		return "!=", "cmp-eq-to-ne", true
	case token.NEQ:
		return "==", "cmp-ne-to-eq", true
	case token.LAND:
		return "||", "logic-and-to-or", true
	case token.LOR:
		return "&&", "logic-or-to-and", true
	}
	return "", "", false
}

// neuterEqualityCall rewrites a constant-time / byte comparison call into a
// trivially-passing value, modelling a dropped authentication check.
func neuterEqualityCall(pkg, fn string) (string, bool) {
	switch pkg {
	case "bytes":
		if fn == "Equal" || fn == "EqualFold" {
			return "true", true
		}
	case "hmac":
		if fn == "Equal" {
			return "true", true
		}
	case "subtle":
		switch fn {
		case "ConstantTimeCompare", "ConstantTimeEq", "ConstantTimeByteEq":
			return "1", true // these return 1 for "equal"
		}
	}
	return "", false
}

// bumpInt returns replacement integer literals (value+1, and 0 when non-zero)
// for a bound constant.
func bumpInt(lit string) []string {
	n, err := strconv.ParseInt(lit, 0, 64)
	if err != nil {
		return nil
	}
	out := []string{strconv.FormatInt(n+1, 10)}
	if n != 0 {
		out = append(out, "0")
	}
	return out
}

func resultsHaveError(ft *ast.FuncType) bool {
	if ft.Results == nil {
		return false
	}
	for _, f := range ft.Results.List {
		if id, ok := f.Type.(*ast.Ident); ok && id.Name == "error" {
			return true
		}
	}
	return false
}

func bodyReturns(b *ast.BlockStmt) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		if _, ok := n.(*ast.ReturnStmt); ok {
			found = true
		}
		return true
	})
	return found
}

func isGenerated(src []byte) bool {
	// Matches the `// Code generated ... DO NOT EDIT.` convention (gofmt/go
	// generate), checked only in the leading comment region.
	head := src
	if len(head) > 2048 {
		head = head[:2048]
	}
	for _, line := range strings.Split(string(head), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "// Code generated") && strings.HasSuffix(line, "DO NOT EDIT.") {
			return true
		}
	}
	return false
}

// selectMutations caps the mutation set to at most max entries. When capping is
// needed it samples deterministically from seed, then restores sorted order for
// a stable report.
func selectMutations(all []Mutation, max int, seed int64) []Mutation {
	if max <= 0 || len(all) <= max {
		return all
	}
	idx := make([]int, len(all))
	for i := range idx {
		idx[i] = i
	}
	r := rand.New(rand.NewSource(seed))
	r.Shuffle(len(idx), func(i, j int) { idx[i], idx[j] = idx[j], idx[i] })
	idx = idx[:max]
	sort.Ints(idx)
	out := make([]Mutation, 0, max)
	for _, i := range idx {
		out = append(out, all[i])
	}
	return out
}
