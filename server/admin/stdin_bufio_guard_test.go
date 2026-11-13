package admin

// Rollout of the #4151 stdin guard (cli/cmd TestNoDirectBufioOverStdin) to the three
// non-CLI files that still build a bufio reader or scanner directly over os.Stdin. Such a
// reader reads ahead, and what it buffered is lost when the next prompt builds its own
// (#3448, #4126). It runs report-only (docs/guard-rollout.d), so the three known sites
// below are logged, not failed, until each is moved to a shared reader by its owner.
//
// What it checks: in the listed files, a call to bufio.NewReader, bufio.NewReaderSize or
// bufio.NewScanner whose first argument is the selector os.Stdin, matched on the syntax
// tree so comments and strings never trip it. Files with a //go:build ignore line are
// parsed all the same.
//
// What it does not check: a reader built over some other value that happens to be stdin
// (cmd.InOrStdin(), a variable holding os.Stdin, an io.Reader parameter), and files not
// listed in stdinGuardFiles.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// stdinGuardFiles are the files this rollout covers, relative to this directory.
var stdinGuardFiles = []string{
	"recover_admin.go",
	"testhook.go",
	"../../scripts/analysis/remote_storage_classify.go",
}

// stdinBufioUses returns "file:line: bufio.X(os.Stdin)" for every offending call in src.
func stdinBufioUses(filename string, src any) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var hits []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		fn, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := fn.X.(*ast.Ident)
		if !ok || pkg.Name != "bufio" {
			return true
		}
		switch fn.Sel.Name {
		case "NewReader", "NewReaderSize", "NewScanner":
		default:
			return true
		}
		arg, ok := call.Args[0].(*ast.SelectorExpr)
		if !ok || arg.Sel.Name != "Stdin" {
			return true
		}
		if x, ok := arg.X.(*ast.Ident); !ok || x.Name != "os" {
			return true
		}
		hits = append(hits, fset.Position(call.Pos()).String()+": bufio."+fn.Sel.Name+"(os.Stdin)")
		return true
	})
	return hits, nil
}

func TestNoDirectBufioOverStdin_AdminAndScripts(t *testing.T) {
	g := guardrules.Rollout(t)
	var hits []string
	for _, name := range stdinGuardFiles {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v (the guard is looking in the wrong place, or the file moved: update stdinGuardFiles)", name, err)
		}
		h, err := stdinBufioUses(name, src)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		hits = append(hits, h...)
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		g.Errorf("a bufio reader built over os.Stdin loses the input it buffered when the next prompt builds its own (#3448, #4126).\n"+
			"Use one shared reader per process instead:\n  %s", strings.Join(hits, "\n  "))
	}
}

// Calibration: the detector must fire on the planted violation and stay quiet on the
// planted-clean source, or the report-only run means nothing. It uses t directly, never
// the rollout wrapper, so it is always blocking.
func TestNoDirectBufioOverStdin_AdminAndScripts_Calibration(t *testing.T) {
	const red = `//go:build ignore

package x

import (
	"bufio"
	"os"
)

func prompt() string {
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return line
}

func scan() bool { return bufio.NewScanner(os.Stdin).Scan() }

func sized() { _ = bufio.NewReaderSize(os.Stdin, 4096) }
`
	const green = `package x

import (
	"bufio"
	"os"
	"strings"
)

// bufio.NewReader(os.Stdin) in a comment is not a call.
const doc = "bufio.NewReader(os.Stdin)"

func fromString() *bufio.Reader { return bufio.NewReader(strings.NewReader("x")) }

func fromFile(f *os.File) *bufio.Scanner { return bufio.NewScanner(f) }

func stdoutIsFine() *bufio.Writer { return bufio.NewWriter(os.Stdout) }
`
	hits, err := stdinBufioUses("red.go", red)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 3 {
		t.Errorf("red source: want 3 findings (NewReader, NewScanner, NewReaderSize), got %d: %v", len(hits), hits)
	}
	hits, err = stdinBufioUses("green.go", green)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("green source: want no findings, got %v", hits)
	}
}
