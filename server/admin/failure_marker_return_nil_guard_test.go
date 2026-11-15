package admin

// Guard for the #4270 class: a command that prints a failure line and then returns nil exits 0,
// so a preflight `encryption status && encryption rotate --confirm` carries on past a failed check
// (`encryption status` and `encryption init` did exactly that).
//
// What it checks: in every non-test .go file of this directory and of internal/encryptionops,
// inside an exported function whose name ends in WithConfig or an unexported function named
// run<Upper>..., a `return nil` that is the statement directly after a fmt.Printf, fmt.Println or
// fmt.Print call whose first argument is a string literal starting with "❌". Matched on the
// syntax tree, so comments and strings never trip it; a comment between the two statements does
// not hide the pair.
//
// What it does not check: a "⚠️" line (those are often advisory, see the per-site comments in
// internal/encryptionops), a failure line printed through another call (fmt.Fprintf, a helper, a
// logger) or built from a non-literal, a `return nil` that is not the next statement (an
// intervening statement, or a nil error named in a variable), a function outside the two name
// shapes, and any file outside these two directories. Sites that are advisory by design are
// exempt by not matching, not by an allowlist: a "❌" line followed by `return nil` has none.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// failureMarkerGuardDirs are the directories scanned, relative to this directory.
var failureMarkerGuardDirs = []string{".", "../../internal/encryptionops"}

// guardedCommandFunc reports whether name is an exported *WithConfig function or an unexported
// run<Upper>... function.
func guardedCommandFunc(name string) bool {
	if ast.IsExported(name) {
		return strings.HasSuffix(name, "WithConfig")
	}
	rest, ok := strings.CutPrefix(name, "run")
	if !ok || rest == "" {
		return false
	}
	return unicode.IsUpper([]rune(rest)[0])
}

// isFailureMarker reports whether s is fmt.Printf/Println/Print("❌ ...").
func isFailureMarker(s ast.Stmt) bool {
	es, ok := s.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	fn, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := fn.X.(*ast.Ident); !ok || pkg.Name != "fmt" {
		return false
	}
	switch fn.Sel.Name {
	case "Printf", "Println", "Print":
	default:
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	text, err := strconv.Unquote(lit.Value)
	return err == nil && strings.HasPrefix(text, "❌")
}

// isReturnNil reports whether s is a bare `return nil`.
func isReturnNil(s ast.Stmt) bool {
	ret, ok := s.(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	id, ok := ret.Results[0].(*ast.Ident)
	return ok && id.Name == "nil"
}

// failureMarkerReturnNil returns "pos (in func)" for every guarded function statement list in
// which a "❌" print is directly followed by `return nil`.
func failureMarkerReturnNil(filename string, src any) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var hits []string
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil || !guardedCommandFunc(fd.Name.Name) {
			continue
		}
		check := func(list []ast.Stmt) {
			for i := 0; i+1 < len(list); i++ {
				if isFailureMarker(list[i]) && isReturnNil(list[i+1]) {
					hits = append(hits, fset.Position(list[i+1].Pos()).String()+" (in "+fd.Name.Name+")")
				}
			}
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BlockStmt:
				check(x.List)
			case *ast.CaseClause:
				check(x.Body)
			case *ast.CommClause:
				check(x.Body)
			}
			return true
		})
	}
	sort.Strings(hits)
	return hits, nil
}

func TestNoReturnNilAfterFailureMarker_EncryptionAdmin(t *testing.T) {
	g := guardrules.Rollout(t)
	scanned := 0
	var hits []string
	for _, dir := range failureMarkerGuardDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			src, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			h, err := failureMarkerReturnNil(name, src)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			scanned++
			hits = append(hits, h...)
		}
	}
	if scanned == 0 {
		t.Fatal("no .go files found: the guard is running in the wrong directory, or failureMarkerGuardDirs is stale")
	}
	if len(hits) > 0 {
		g.Errorf("a command that prints a \"❌\" failure line and then returns nil exits 0 (#4270): a preflight `status && rotate --confirm` continues past the failed check.\n"+
			"Return the error after printing. If the line is advisory (the command still did its job), print \"⚠️\" instead:\n  %s",
			strings.Join(hits, "\n  "))
	}
}

// Calibration: the detector must fire on the planted violations and stay quiet on the
// planted-clean source, or the guard means nothing. It uses t directly, never the rollout
// wrapper, so it is always blocking.
func TestNoReturnNilAfterFailureMarker_EncryptionAdmin_Calibration(t *testing.T) {
	const red = `package x

import "fmt"

func StatusWithConfig() error {
	if bad() {
		fmt.Printf("❌ %v\n", errBad)
		return nil
	}
	return nil
}

func InitWithConfig() error {
	if bad() {
		fmt.Println("❌ Encryption is disabled in configuration")
		// a comment between the two statements does not hide the pair
		return nil
	}
	return nil
}

func runEncStatus() error {
	switch {
	case bad():
		fmt.Print("❌ bad")
		return nil
	}
	return nil
}
`
	const green = `package x

import (
	"fmt"
	"os"
)

func StatusWithConfig() error {
	fmt.Printf("❌ %v\n", errBad)
	return errBad
}

// advisory: a warning line, not a failure line
func RotateKEKWithConfig() error {
	fmt.Printf("⚠️  %v\n", errBad)
	return nil
}

// the failure marker is not directly followed by return nil
func ValidateWithConfig() error {
	fmt.Println("❌ not yet")
	cleanup()
	return nil
}

// a print to stderr through another call is out of scope
func MigrateWithConfig() error {
	fmt.Fprintln(os.Stderr, "❌ x")
	return nil
}

// not a guarded name: neither *WithConfig nor run<Upper>
func printStatus() error {
	fmt.Println("❌ x")
	return nil
}

func runner() error {
	fmt.Println("❌ x")
	return nil
}

// "❌" in a comment or a string that is not the first argument is not a marker
// fmt.Println("❌ x"); return nil
func DisabledWithConfig() error {
	fmt.Printf("%s", "❌")
	return nil
}

func okWithConfig() error {
	fmt.Println("❌ x")
	return nil
}
`
	hits, err := failureMarkerReturnNil("red.go", red)
	if err != nil {
		t.Fatal(err)
	}
	var funcs []string
	for _, h := range hits {
		funcs = append(funcs, h[strings.LastIndex(h, "(in ")+4:len(h)-1])
	}
	sort.Strings(funcs)
	if got, want := strings.Join(funcs, " "), "InitWithConfig StatusWithConfig runEncStatus"; got != want {
		t.Errorf("red source: want hits in %q (Printf, Println after a comment, Print in a case clause), got %q", want, got)
	}

	hits, err = failureMarkerReturnNil("green.go", green)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("green source: want no findings, got %v", hits)
	}
}
