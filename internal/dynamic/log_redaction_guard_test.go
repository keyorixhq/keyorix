package dynamic

// log_redaction_guard_test.go — Group 1's guard for the SQL/driver-error
// redaction boundary: server/http/handlers/dynamic_secrets.go and
// internal/core/dynamic_secrets.go both log dynamic-secret backend/driver
// errors (postgres/mysql/mongodb/redis, via internal/dynamic's engines) with
// log.Printf/log.Println. Before this package's RedactSensitive/
// SanitizeErrorMessage existed, several of those call sites formatted the raw
// error with %v directly -- and a raw pgx/go-sql-driver/mongo-driver/go-redis
// error CAN, on a future driver bump or a 5th backend, echo a DSN/connection-
// string credential fragment straight into the server log (see this
// package's own doc comment and redact.go).
//
// This guard is deliberately NOT type-aware (no go/packages type-checking --
// that would pull go/packages/golang.org/x/tools into the root module purely
// for a test, disproportionate to this fix's scope). Instead it recognizes,
// by AST shape, exactly the call forms the real call sites in this repo use
// today, the same way server/http/raw_storage_bypass_guard_test.go's
// identifier-tracking and readShapedStoragePrefixes heuristics do:
//
//   - Any argument to log.Printf/log.Println that is a bare identifier whose
//     name contains "err" (case-insensitive) -- covers err, gerr, rerr, eerr,
//     the naming convention every error-returning call in these files uses --
//     is flagged UNLESS it is passed through dynamic.SanitizeErrorMessage(...)
//     first.
//   - Any argument that is a direct `<x>.Error()` call is flagged the same way.
//
// A flagged argument means a raw driver/backend error can reach this log call
// unsanitized -- exactly the Group 1 defect. The two recognized shapes are
// exhaustive over the actual code in scope today (verified: every log.Printf/
// log.Println call in the three scanned locations that logs an error uses one
// of exactly these two shapes -- confirmed by this guard passing after the
// fix and failing before it, not assumed).
//
// Scope: internal/dynamic/*.go (today: zero log calls at all -- this guard
// keeps it that way, or requires sanitization if that ever changes),
// internal/core/dynamic_secrets.go, and server/http/handlers/dynamic_secrets.go
// -- the exact files QUEUE.md's Group 1 investigation cited.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dynamicSecretLogSites are the (directory, single-file-or-empty) scan
// targets. An empty file name scans every non-test *.go file in the
// directory; a non-empty one scans exactly that file.
var dynamicSecretLogSites = []struct {
	dir  string
	file string // "" = every non-test *.go file in dir
}{
	{dir: ".", file: ""}, // internal/dynamic itself
	{dir: filepath.Join("..", "core"), file: "dynamic_secrets.go"},
	{dir: filepath.Join("..", "..", "server", "http", "handlers"), file: "dynamic_secrets.go"},
}

// unsanitizedLogCall names one flagged log.Printf/log.Println argument.
type unsanitizedLogCall struct {
	file string
	line int
	desc string
}

// isSanitizeErrorMessageCall reports whether e is a call to (possibly
// package-qualified) SanitizeErrorMessage(...) -- the one recognized "this
// argument is already safe to log" shape.
func isSanitizeErrorMessageCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "SanitizeErrorMessage"
	case *ast.SelectorExpr:
		return fn.Sel.Name == "SanitizeErrorMessage"
	}
	return false
}

// looksLikeErrorArg reports whether e, NOT already wrapped by
// SanitizeErrorMessage, looks like it carries a raw error's text: a bare
// identifier whose name contains "err" (case-insensitive -- covers err,
// gerr, rerr, eerr), or a direct `<x>.Error()` call.
func looksLikeErrorArg(e ast.Expr) (string, bool) {
	if isSanitizeErrorMessageCall(e) {
		return "", false
	}
	switch v := e.(type) {
	case *ast.Ident:
		if strings.Contains(strings.ToLower(v.Name), "err") {
			return "bare identifier %q", true
		}
	case *ast.CallExpr:
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
			return "direct .Error() call", true
		}
	}
	return "", false
}

// findUnsanitizedLogCalls walks file, flagging every log.Printf/log.Println
// argument that looksLikeErrorArg.
func findUnsanitizedLogCalls(fset *token.FileSet, file *ast.File, path string) []unsanitizedLogCall {
	var found []unsanitizedLogCall
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "log" || (sel.Sel.Name != "Printf" && sel.Sel.Name != "Println") {
			return true
		}
		for _, arg := range call.Args {
			if desc, flagged := looksLikeErrorArg(arg); flagged {
				pos := fset.Position(arg.Pos())
				found = append(found, unsanitizedLogCall{
					file: path,
					line: pos.Line,
					desc: desc,
				})
			}
		}
		return true
	})
	return found
}

// TestNoUnsanitizedDriverErrorReachesLog is Group 1's guard: no raw
// dynamic-secret backend/driver error may reach a log.Printf/log.Println call
// in internal/dynamic or the dynamic-secret HTTP/core call sites without
// first going through dynamic.SanitizeErrorMessage. See this file's package
// comment for exactly what is (and isn't) recognized, and why.
func TestNoUnsanitizedDriverErrorReachesLog(t *testing.T) {
	fset := token.NewFileSet()
	var all []unsanitizedLogCall
	scanned := 0

	for _, site := range dynamicSecretLogSites {
		var paths []string
		if site.file != "" {
			paths = []string{filepath.Join(site.dir, site.file)}
		} else {
			entries, err := os.ReadDir(site.dir)
			if err != nil {
				t.Fatalf("reading %s: %v", site.dir, err)
			}
			for _, e := range entries {
				name := e.Name()
				if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
					continue
				}
				paths = append(paths, filepath.Join(site.dir, name))
			}
		}
		for _, p := range paths {
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", p, err)
			}
			scanned++
			all = append(all, findUnsanitizedLogCalls(fset, f, p)...)
		}
	}

	if scanned < 2 {
		t.Fatalf("only scanned %d file(s) -- the scan list above likely broke silently (expected at least "+
			"internal/dynamic's own files plus the two named cross-package files)", scanned)
	}
	for _, f := range all {
		t.Errorf("%s:%d: log call argument (%s) looks like an unsanitized error -- "+
			"wrap it with dynamic.SanitizeErrorMessage(...) before logging (Group 1: raw driver/backend "+
			"errors must never reach a log call verbatim)", f.file, f.line, f.desc)
	}
}
