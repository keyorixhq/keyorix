// Package clientguard mechanically enforces INV-CLI-06 (#2525): every CLI subcommand talks to
// the server through the one client newAPIClient (cli/cmd/client.go) builds -- the hardened
// transport from apiclient.NewHardenedHTTPClient, with the bearer token attached by one
// request editor -- never through an HTTP call it rolls itself.
//
// The guard asserts the CONDITION that makes "every mutating subcommand uses newAPIClient"
// true, not the conclusion: if nothing outside newAPIClient can construct an apiclient
// client, build a raw request, or reach a net/http transport, then every server call any
// subcommand makes necessarily goes through a client newAPIClient built. A per-command
// "does this RunE call newAPIClient" check would be weaker -- it would pass a command that
// calls newAPIClient AND separately rolls its own http.Post.
//
// Scope: every non-_test .go file in the cli module, except internal/apiclient/ (the
// transport layer itself: generated client plus the hardened http.Client). It is a source
// walk with go/parser, not a grep, so import aliases are resolved per file.
//
// Shapes this sweep recognises (how the list was derived: every way Go code in this module
// can reach the network is (1) a package that opens connections, (2) net/http's client
// surface, or (3) the generated apiclient's own constructors and raw-request builders):
//
//  1. Importing "net" or any "net/..." package other than net/http and net/url, or
//     "crypto/tls" -- each is a way to build a transport or dial without net/http.
//  2. Any net/http selector outside newAPIClient other than the Status*/Method* constants
//     (so http.Client, http.Get/Post/Head/PostForm, http.NewRequest*, http.DefaultClient,
//     http.Transport, ... are all flagged). A dot-import of net/http is flagged outright.
//  3. Any apiclient selector beginning New or With outside newAPIClient -- NewClient,
//     NewClientWithResponses, NewHardenedHTTPClient, WithHTTPClient, WithRequestEditorFn,
//     and the generated New<Op>Request raw-request builders -- plus a composite literal of
//     apiclient.Client / apiclient.ClientWithResponses.
//
// What it does NOT catch, by design: shelling out (os/exec running curl), cgo, reflection,
// or a hypothetical new third-party HTTP library -- the last one is also caught by
// depguard-style review of go.mod, not here. It also does not police test files, which
// legitimately use net/http/httptest.
package clientguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	apiclientPath  = "github.com/keyorixhq/keyorix/cli/internal/apiclient"
	allowedFunc    = "newAPIClient"
	allowedFuncPkg = "cmd"
)

// forbiddenNetImport reports whether importing path is a way to reach the network without
// going through net/http (rule 1).
func forbiddenNetImport(path string) bool {
	if path == "net/http" || path == "net/url" {
		return false
	}
	return path == "net" || strings.HasPrefix(path, "net/") || path == "crypto/tls"
}

type violation struct {
	pos  token.Position
	what string
}

// sweepFile returns every rule violation in one parsed file. Only the top-level
// `func newAPIClient` in package cmd is exempt from rules 2 and 3; rule 1 has no exemption.
func sweepFile(fset *token.FileSet, f *ast.File) []violation {
	var out []violation
	httpNames := map[string]bool{}
	apiNames := map[string]bool{}

	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		pos := fset.Position(imp.Pos())
		if forbiddenNetImport(path) {
			out = append(out, violation{pos, "imports " + path})
			continue
		}
		local := ""
		if imp.Name != nil {
			local = imp.Name.Name
		}
		switch path {
		case "net/http":
			if local == "." {
				out = append(out, violation{pos, "dot-imports net/http"})
				continue
			}
			if local == "" {
				local = "http"
			}
			httpNames[local] = true
		case apiclientPath:
			if local == "." {
				out = append(out, violation{pos, "dot-imports apiclient"})
				continue
			}
			if local == "" {
				local = "apiclient"
			}
			apiNames[local] = true
		}
	}
	if len(httpNames) == 0 && len(apiNames) == 0 {
		return out
	}

	check := func(root ast.Node) {
		ast.Inspect(root, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				id, ok := x.X.(*ast.Ident)
				if !ok {
					return true
				}
				name := x.Sel.Name
				switch {
				case httpNames[id.Name]:
					if !strings.HasPrefix(name, "Status") && !strings.HasPrefix(name, "Method") {
						out = append(out, violation{fset.Position(x.Pos()), id.Name + "." + name})
					}
				case apiNames[id.Name]:
					if strings.HasPrefix(name, "New") || strings.HasPrefix(name, "With") {
						out = append(out, violation{fset.Position(x.Pos()), id.Name + "." + name})
					}
				}
			case *ast.CompositeLit:
				typ := x.Type
				if u, ok := typ.(*ast.StarExpr); ok {
					typ = u.X
				}
				if sel, ok := typ.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && apiNames[id.Name] &&
						(sel.Sel.Name == "Client" || sel.Sel.Name == "ClientWithResponses") {
						out = append(out, violation{fset.Position(x.Pos()), id.Name + "." + sel.Sel.Name + "{...} literal"})
					}
				}
			}
			return true
		})
	}

	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil &&
			fd.Name.Name == allowedFunc && f.Name.Name == allowedFuncPkg {
			continue
		}
		check(decl)
	}
	return out
}

func TestNoHTTPClientOutsideNewAPIClient(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	var violations []string
	scanned, apiclientUsers := 0, 0
	foundAllowed := false

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel == filepath.Join("internal", "apiclient") || d.Name() == "testdata" ||
				(strings.HasPrefix(d.Name(), ".") && rel != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		scanned++
		for _, imp := range f.Imports {
			if imp.Path.Value == strconv.Quote(apiclientPath) {
				apiclientUsers++
			}
		}
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil &&
				fd.Name.Name == allowedFunc && f.Name.Name == allowedFuncPkg {
				foundAllowed = true
			}
		}
		for _, v := range sweepFile(fset, f) {
			p := v.pos
			if r, err := filepath.Rel(root, p.Filename); err == nil {
				p.Filename = r
			}
			violations = append(violations, p.String()+": "+v.what)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	// Non-vacuity: the sweep is only meaningful if it actually saw the code it guards.
	if !foundAllowed {
		t.Fatalf("func %s not found in package %s -- the sweep's one exemption names a function that no longer exists; update this guard alongside the rename", allowedFunc, allowedFuncPkg)
	}
	if scanned < 50 || apiclientUsers < 20 {
		t.Fatalf("sweep scanned only %d files (%d importing apiclient) -- expected the whole cli module; is the walk root wrong?", scanned, apiclientUsers)
	}
	if len(violations) > 0 {
		t.Fatalf("INV-CLI-06: server calls must go through newAPIClient (cli/cmd/client.go); found %d raw HTTP/client construction site(s):\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// TestSweepFileCatchesEachShape is the calibration half: one planted snippet per recognised
// shape must be flagged, and the shapes that are legitimately allowed must not be -- so the
// guard is proven red on known-bad input and green on known-good input in-tree, not only
// on a scratch branch.
func TestSweepFileCatchesEachShape(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantHit bool
	}{
		{"http.Post", `package cmd; import "net/http"; func f() { http.Post("u", "", nil) }`, true},
		{"aliased http.Client literal", `package cmd; import h "net/http"; func f() { _ = &h.Client{} }`, true},
		{"http.NewRequest", `package cmd; import "net/http"; func f() { http.NewRequest("GET", "u", nil) }`, true},
		{"http.DefaultClient", `package cmd; import "net/http"; func f() { _ = http.DefaultClient }`, true},
		{"dot-import net/http", `package cmd; import . "net/http"; func f() {}`, true},
		{"net/http/httputil", `package cmd; import "net/http/httputil"; func f() { _ = httputil.DumpRequest }`, true},
		{"crypto/tls", `package cmd; import "crypto/tls"; var _ tls.Config`, true},
		{"net dial", `package cmd; import "net"; func f() { net.Dial("tcp", "x") }`, true},
		{"apiclient.NewClientWithResponses elsewhere", `package cmd; import "github.com/keyorixhq/keyorix/cli/internal/apiclient"; func other() { apiclient.NewClientWithResponses("u") }`, true},
		{"apiclient raw request builder", `package cmd; import "github.com/keyorixhq/keyorix/cli/internal/apiclient"; func f() { apiclient.NewGetVersionRequest("u") }`, true},
		{"apiclient.Client literal", `package cmd; import "github.com/keyorixhq/keyorix/cli/internal/apiclient"; func f() { _ = &apiclient.Client{} }`, true},
		{"newAPIClient in another package", `package other; import "github.com/keyorixhq/keyorix/cli/internal/apiclient"; func newAPIClient() { apiclient.NewClient("u") }`, true},
		{"newAPIClient method, not func", `package cmd; import "github.com/keyorixhq/keyorix/cli/internal/apiclient"; type T struct{}; func (T) newAPIClient() { apiclient.NewClient("u") }`, true},

		{"status constant", `package cmd; import "net/http"; var _ = http.StatusOK`, false},
		{"method constant", `package cmd; import "net/http"; var _ = http.MethodGet`, false},
		{"net/url", `package cmd; import "net/url"; func f() { url.Parse("x") }`, false},
		{"generated method call", `package cmd; import "github.com/keyorixhq/keyorix/cli/internal/apiclient"; func f(c *apiclient.ClientWithResponses) { _ = c }`, false},
		{"apiclient type reference", `package cmd; import "github.com/keyorixhq/keyorix/cli/internal/apiclient"; var _ apiclient.CreateSecretJSONRequestBody`, false},
		{"newAPIClient itself", `package cmd; import ("net/http"; "github.com/keyorixhq/keyorix/cli/internal/apiclient"); func newAPIClient() { apiclient.NewClientWithResponses("u", apiclient.WithHTTPClient(apiclient.NewHardenedHTTPClient())); var _ *http.Request }`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := sweepFile(fset, f)
			if tc.wantHit && len(got) == 0 {
				t.Fatalf("expected a violation, got none")
			}
			if !tc.wantHit && len(got) != 0 {
				t.Fatalf("expected no violation, got %v", got)
			}
		})
	}
}

// moduleRoot returns this module's root directory, derived via `go env GOMOD` (same
// approach as internal/depguard) so the walk does not depend on this package's location.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Fatalf("go env GOMOD returned no module (got %q) -- is this test running inside the cli module?", gomod)
	}
	return filepath.Dir(gomod)
}
