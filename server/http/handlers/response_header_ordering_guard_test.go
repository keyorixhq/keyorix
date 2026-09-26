// response_header_ordering_guard_test.go — static guard against the class of
// bug this package's WriteHeader-before-sendSuccess fix closed (ADR-108
// switch-branch smoke gate, 2026-09-25): a handler that calls
// w.WriteHeader(...) and THEN a call that tries to set response headers
// (sendSuccess/sendError/sendCreated -- each of which does
// w.Header().Set(...) internally) silently ships the wrong (or missing)
// Content-Type, because Go drops header mutations made after WriteHeader.
// json.Decoder-based tests never catch this (it doesn't check Content-Type
// before decoding a body that happens to be valid JSON regardless of its
// declared type) -- only a real client that gates on the header, like
// oapi-codegen's generated ParseXResponse functions, does. See
// secrets_crud.go's history (this same commit) for the real-world instance.
//
// What this DOES check: every WriteHeader(...) call in every non-test
// server/http/handlers/*.go file, and whether a call to sendSuccess/
// sendError/sendCreated (by name, package-level OR a method on any receiver)
// appears AFTER it as a later statement in the same or an enclosing block.
//
// What this does NOT check: a raw inline w.Header().Set(...) call after
// WriteHeader (no real instance of that shape exists in this package today,
// only calls through the three named helpers); handler files outside
// server/http/handlers (server/http's own top-level package, e.g.
// bulk_delete_handler_test.go's helpers, is not scanned); and it cannot
// verify a DIFFERENT header-mutating helper added later under a new name --
// extend headerMutatingCallNames if one is.
package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// headerMutatingCallNames are the functions/methods this package uses to set
// response headers -- each does w.Header().Set(...) before writing a body.
var headerMutatingCallNames = map[string]bool{
	"sendSuccess": true,
	"sendError":   true,
	"sendCreated": true,
}

// handlerSourceFiles returns every non-test .go file directly in this
// package's directory.
func handlerSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading handlers dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	return files
}

// callName returns the identifier a call expression invokes: "foo" for
// foo(...), "bar" for x.bar(...), "" for anything else (e.g. a call through
// a more complex expression this guard doesn't need to recognize).
func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	default:
		return ""
	}
}

// isWriteHeaderCall reports whether stmt is a bare `X.WriteHeader(...)` call.
func isWriteHeaderCall(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	return callName(call) == "WriteHeader"
}

// isHeaderMutatingCall reports whether stmt calls one of headerMutatingCallNames.
func isHeaderMutatingCall(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	return headerMutatingCallNames[callName(call)]
}

// checkBlockOrdering recurses into every block (function bodies, if/else,
// for, switch case bodies, ...) and, within EACH block independently, flags
// a headerMutatingCallNames call that appears after an earlier
// WriteHeader(...) call in that same block's statement list -- exactly the
// shape every real instance of this bug took (two adjacent or near-adjacent
// statements in one straight-line block), not a fully general control-flow
// analysis.
func checkBlockOrdering(t *testing.T, file, fnName string, block *ast.BlockStmt) {
	t.Helper()
	sawWriteHeader := false
	for _, stmt := range block.List {
		if isWriteHeaderCall(stmt) {
			sawWriteHeader = true
		} else if sawWriteHeader && isHeaderMutatingCall(stmt) {
			t.Errorf("%s: func %s calls WriteHeader(...) and then a header-setting call "+
				"(sendSuccess/sendError/sendCreated) afterward in the same block -- Go "+
				"silently drops header mutations made after WriteHeader, so this ships "+
				"the wrong Content-Type. Set headers (via sendCreated, or Header().Set "+
				"followed by your own WriteHeader) BEFORE calling WriteHeader, not after.",
				file, fnName)
		}
		// Recurse into every nested block this statement might contain, so a
		// WriteHeader+header-call pair inside an `if err != nil { ... }` (the
		// actual shape two of the real instances took) is still caught, scoped
		// to that inner block independently of the outer one.
		ast.Inspect(stmt, func(n ast.Node) bool {
			if inner, ok := n.(*ast.BlockStmt); ok && inner != block {
				checkBlockOrdering(t, file, fnName, inner)
			}
			return true
		})
	}
}

// TestNoWriteHeaderBeforeHeaderMutatingCall is this guard's real check: parses
// every handler source file and walks every function/method body.
func TestNoWriteHeaderBeforeHeaderMutatingCall(t *testing.T) {
	fset := token.NewFileSet()
	for _, name := range handlerSourceFiles(t) {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			checkBlockOrdering(t, name, fn.Name.Name, fn.Body)
		}
	}
}
