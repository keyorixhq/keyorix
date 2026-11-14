package cmd

// Static guard for the lost-buffered-input bug of #3448/#4126: a bufio reader or scanner built
// directly over os.Stdin reads ahead, and whatever it buffered is gone when the next prompt
// builds its own. Every prompt must go through stdinReader()/promptInput() (stdin_reader.go).
//
// What it checks: in every .go file of this package except stdin_reader.go, a call to
// bufio.NewReader, bufio.NewReaderSize or bufio.NewScanner whose first argument is the
// selector os.Stdin. The match is on the syntax tree, so comments and strings never trip it.
//
// What it does not check: a reader built over some other value that happens to be stdin
// (cmd.InOrStdin(), a variable holding os.Stdin, an io.Reader parameter). promptInput
// already covers the cobra case; a new shape would need a new rule here.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// stdinReaderFile is the one file allowed to build a bufio reader over os.Stdin.
const stdinReaderFile = "stdin_reader.go"

// directStdinBufioUses returns "file:line: bufio.X(os.Stdin)" for every offending call in src.
func directStdinBufioUses(filename string, src any) ([]string, error) {
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

func TestNoDirectBufioOverStdin(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	scanned := 0
	for _, name := range files {
		if name == stdinReaderFile {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		h, err := directStdinBufioUses(name, src)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		hits = append(hits, h...)
		scanned++
	}
	if scanned < 20 { // the package has far more files; fewer means the glob scanned the wrong directory
		t.Fatalf("scanned only %d files: the guard is looking in the wrong place", scanned)
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		t.Errorf("a bufio reader built over os.Stdin loses the input it buffered when the next prompt builds its own (#3448, #4126).\n"+
			"Use stdinReader() or promptInput(cmd.InOrStdin()) from %s instead:\n  %s",
			stdinReaderFile, strings.Join(hits, "\n  "))
	}
}

// scriptsStdinFiles are the files outside this package that the same rule is extended to
// (report-only first, docs/guard-rollout.d/TestNoDirectBufioOverStdin_Scripts.tsv).
// Only this one so far: server/admin/recover_admin.go and server/admin/testhook.go have the
// same shape and are listed as leftovers until the server/admin owners are done.
//
// The script reads stdin once, to EOF, through a single scanner, so it cannot lose input to a
// second reader the way a prompt sequence does; it is listed because the rule is syntactic
// and a later second read in it would be the bug. What it does not check: any file not named
// here.
var scriptsStdinFiles = []string{"scripts/analysis/remote_storage_classify.go"}

func TestNoDirectBufioOverStdin_Scripts(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()
	var hits []string
	for _, rel := range scriptsStdinFiles {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("the guard is looking in the wrong place: %v", err) // not a finding
		}
		h, err := directStdinBufioUses(rel, src)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		hits = append(hits, h...)
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		g.Errorf("a bufio reader built over os.Stdin loses the input it buffered when the next reader is built (#3448, #4126):\n  %s",
			strings.Join(hits, "\n  "))
	}
}

// Calibration: the detector must fire on the planted violation and stay quiet on the
// planted-clean source, or a green TestNoDirectBufioOverStdin means nothing.
func TestNoDirectBufioOverStdin_Calibration(t *testing.T) {
	const red = `package cmd

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
	const green = `package cmd

import (
	"bufio"
	"os"
	"strings"
)

// bufio.NewReader(os.Stdin) in a comment is not a call.
const doc = "bufio.NewReader(os.Stdin)"

func prompt() string {
	line, _ := stdinReader().ReadString('\n')
	return line
}

func fromString() *bufio.Reader { return bufio.NewReader(strings.NewReader("x")) }

func fromFile(f *os.File) *bufio.Scanner { return bufio.NewScanner(f) }

func stdoutIsFine() *bufio.Writer { return bufio.NewWriter(os.Stdout) }
`
	hits, err := directStdinBufioUses("red.go", red)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 3 {
		t.Errorf("red source: want 3 findings (NewReader, NewScanner, NewReaderSize), got %d: %v", len(hits), hits)
	}
	hits, err = directStdinBufioUses("green.go", green)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("green source: want no findings, got %v", hits)
	}
}
