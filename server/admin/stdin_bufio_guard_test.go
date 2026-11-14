package admin

// Rollout of the #4151 stdin guard (cli/cmd TestNoDirectBufioOverStdin) to server/admin and
// scripts/analysis/remote_storage_classify.go. A bufio reader or scanner built directly over
// os.Stdin reads ahead, and what it buffered is lost when the next prompt builds its own
// (#3448, #4126). New sites fail; the three existing ones are allowlisted below by file and
// enclosing func, because each builds the only stdin reader of its process and reads once,
// so there is no second reader to lose input to.
//
// What it checks: in every non-test .go file of this directory plus stdinGuardExtraFiles,
// a call to bufio.NewReader, bufio.NewReaderSize or bufio.NewScanner whose first argument is
// the selector os.Stdin, matched on the syntax tree so comments and strings never trip it.
// Files with a //go:build ignore line are parsed all the same. An allowlist entry whose func
// no longer has such a call is reported stale, so the list cannot outlive the code.
//
// What it does not check: a reader built over some other value that happens to be stdin
// (cmd.InOrStdin(), a variable holding os.Stdin, an io.Reader parameter), and files outside
// this directory other than stdinGuardExtraFiles.

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
)

// stdinGuardExtraFiles are files outside this directory that the guard also scans,
// relative to this directory.
var stdinGuardExtraFiles = []string{
	"../../scripts/analysis/remote_storage_classify.go",
}

// stdinGuardAllowed maps "file:func" (file as scanned, func as stdinBufioUses names it) to
// the reason that site cannot lose buffered input.
var stdinGuardAllowed = map[string]string{
	"recover_admin.go:readRecoveryKeyFromStdin":              "single stdin read per process (recover-admin, reset-mfa: one call each, no other stdin reader in those commands)",
	"testhook.go:runHoldLockForTest":                         "single stdin read per process (one blocking read that releases the lock)",
	"../../scripts/analysis/remote_storage_classify.go:main": "single stdin read per process (one scanner loop, go:build ignore tool)",
}

// stdinBufioSite is one bufio-over-os.Stdin call: its "file:func" key and its position.
type stdinBufioSite struct {
	key, pos string
}

// stdinBufioUses returns every offending call in src, keyed by filename and enclosing func
// ("Recv.Method" for a method, "" outside any func).
func stdinBufioUses(filename string, src any) ([]stdinBufioSite, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var sites []stdinBufioSite
	for _, decl := range f.Decls {
		funcName := ""
		if fd, ok := decl.(*ast.FuncDecl); ok {
			funcName = fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				funcName = recvTypeName(fd.Recv.List[0].Type) + "." + funcName
			}
		}
		ast.Inspect(decl, func(n ast.Node) bool {
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
			sites = append(sites, stdinBufioSite{
				key: filename + ":" + funcName,
				pos: fset.Position(call.Pos()).String() + ": bufio." + fn.Sel.Name + "(os.Stdin)",
			})
			return true
		})
	}
	return sites, nil
}

// recvTypeName returns the type name of a method receiver (T, *T, T[P] and *T[P] all give T).
func recvTypeName(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.Ident:
			return x.Name
		default:
			return "?"
		}
	}
}

// checkStdinSites returns the sites that are not allowlisted (violations) and the allowlist
// keys that matched no site (stale), both sorted.
func checkStdinSites(sites []stdinBufioSite, allowed map[string]string) (violations, stale []string) {
	seen := map[string]bool{}
	for _, s := range sites {
		if _, ok := allowed[s.key]; ok {
			seen[s.key] = true
			continue
		}
		violations = append(violations, s.pos+" (in "+s.key+")")
	}
	for k := range allowed {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(violations)
	sort.Strings(stale)
	return violations, stale
}

// stdinGuardFiles returns the non-test .go files of this directory plus stdinGuardExtraFiles.
func stdinGuardFiles(t *testing.T) []string {
	t.Helper()
	local, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, name := range local {
		if !strings.HasSuffix(name, "_test.go") {
			files = append(files, name)
		}
	}
	if len(files) == 0 {
		t.Fatal("no .go files found: the guard is running in the wrong directory")
	}
	return append(files, stdinGuardExtraFiles...)
}

func TestNoDirectBufioOverStdin_AdminAndScripts(t *testing.T) {
	g := guardrules.Rollout(t)
	var sites []stdinBufioSite
	for _, name := range stdinGuardFiles(t) {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v (the guard is looking in the wrong place, or the file moved: update stdinGuardExtraFiles)", name, err)
		}
		s, err := stdinBufioUses(name, src)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		sites = append(sites, s...)
	}
	violations, stale := checkStdinSites(sites, stdinGuardAllowed)
	if len(violations) > 0 {
		g.Errorf("a bufio reader built over os.Stdin loses the input it buffered when the next prompt builds its own (#3448, #4126).\n"+
			"Use one shared reader per process instead (or, if this is the only stdin read of its process, add it to stdinGuardAllowed with that reason):\n  %s",
			strings.Join(violations, "\n  "))
	}
	if len(stale) > 0 {
		g.Errorf("stdinGuardAllowed entries no longer match a bufio-over-os.Stdin call (moved, renamed or fixed): delete them:\n  %s",
			strings.Join(stale, "\n  "))
	}
}

// Calibration: the detector must fire on the planted violations and stay quiet on the
// planted-clean source, a planted site outside the allowlist must fire, and an allowlist
// entry with no matching site must be reported stale, or the guard means nothing. It uses
// t directly, never the rollout wrapper, so it is always blocking.
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

type T struct{}

func (*T) sized() { _ = bufio.NewReaderSize(os.Stdin, 4096) }

var top = bufio.NewReader(os.Stdin)
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
	sites, err := stdinBufioUses("red.go", red)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, s := range sites {
		keys = append(keys, s.key)
	}
	sort.Strings(keys)
	if got, want := strings.Join(keys, " "), "red.go: red.go:T.sized red.go:prompt red.go:scan"; got != want {
		t.Errorf("red source: want sites %q (NewReader, NewScanner, NewReaderSize, top-level var), got %q", want, got)
	}

	allowed := map[string]string{"red.go:prompt": "x", "red.go:scan": "x", "red.go:gone": "x"}
	violations, stale := checkStdinSites(sites, allowed)
	if got := strings.Join(violations, "\n"); len(violations) != 2 ||
		!strings.Contains(got, "(in red.go:T.sized)") || !strings.Contains(got, "(in red.go:)") {
		t.Errorf("planted sites outside the allowlist (T.sized, top-level var) must fire and only they, got %v", violations)
	}
	if len(stale) != 1 || stale[0] != "red.go:gone" {
		t.Errorf("an allowlist entry with no matching site must be reported stale, got %v", stale)
	}

	sites, err = stdinBufioUses("green.go", green)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 0 {
		t.Errorf("green source: want no findings, got %v", sites)
	}
}
