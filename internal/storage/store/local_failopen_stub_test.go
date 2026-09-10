// local_failopen_stub_test.go — guards against LocalStorage methods that
// silently return a zero-shaped ("empty", not-an-error) result with no real
// implementation behind them: a fail-open stub masquerading as a working
// query.
//
// remote_unsupported_completeness_test.go and remote_reachability_registry_
// test.go classify every structurally-stub RemoteStorage method — but
// LocalStorage has no equivalent population or guard. That asymmetry let
// storage.Storage.GetRBACAuditLogs's LocalStorage implementation
// (`return nil, 0, nil`, unconditionally, regardless of filter — see this
// repo's fix/remove-dead-rbac-audit-storage-path, which removed the method
// outright as dead code) go unclassified and unguarded for its entire
// lifetime. It had zero production callers throughout, so nothing was ever
// shown the false result — but had a caller appeared, it would have read
// "no RBAC changes" as the true state of the audit trail: an affirmative
// false statement, worse than an error, because it looks like an answer
// instead of a visible gap.
//
// This scans every non-test local_*.go file for *LocalStorage methods whose
// ENTIRE body is a single return statement, all of whose result expressions
// are zero-value literals (nil / 0 / "" / false) — the exact "trivially
// fail-open" shape. No call-graph reachability analysis is needed here,
// unlike the RemoteStorage guards above: a LocalStorage method that never
// touches the DB is visible directly in its own one-line body, not hidden
// behind same-package delegation. The population is asserted to be zero.
package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// localStorageSourceFiles mirrors remoteStorageStubSourceFiles's file-list
// convention (remote_unsupported_completeness_test.go) for the local_*.go
// side: every non-test .go file starting with "local_".
func localStorageSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading .: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if strings.HasPrefix(name, "local_") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files
}

// isZeroValueLiteral reports whether expr is a trivial zero-value literal:
// the bare identifiers nil/false, an integer literal "0", or an empty string
// literal `""`. Deliberately narrow — a real computed value (even one that
// happens to equal zero at runtime, e.g. `return count, nil`) is not a
// literal and does not match.
func isZeroValueLiteral(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "nil" || e.Name == "false"
	case *ast.BasicLit:
		switch e.Kind {
		case token.INT:
			return e.Value == "0"
		case token.STRING:
			return e.Value == `""`
		}
	}
	return false
}

// failOpenLocalStorageStubs returns the name of every *LocalStorage method
// whose entire body is exactly one return statement, all of whose result
// expressions are zero-value literals — a method that silently claims
// success/no-data with no real implementation behind it.
func failOpenLocalStorageStubs(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	var hits []string

	for _, name := range localStorageSourceFiles(t) {
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			if exprString(fn.Recv.List[0].Type) != "*LocalStorage" {
				continue
			}
			if fn.Body == nil || len(fn.Body.List) != 1 {
				continue
			}
			ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) == 0 {
				continue
			}
			allZero := true
			for _, r := range ret.Results {
				if !isZeroValueLiteral(r) {
					allZero = false
					break
				}
			}
			if allZero {
				hits = append(hits, fmt.Sprintf("%s (%s)", fn.Name.Name, name))
			}
		}
	}
	sort.Strings(hits)
	return hits
}

// TestNoFailOpenLocalStorageStubs asserts the population above is empty. See
// this file's package doc for why: a hit here is either a forgotten TODO
// shipped as if it were a real implementation, or a genuine design choice
// (an intentionally-empty result) that deserves an explicit comment and,
// where a caller could be misled, a real error instead of a silent zero
// value — not an unremarked one-line stub indistinguishable from either.
func TestNoFailOpenLocalStorageStubs(t *testing.T) {
	hits := failOpenLocalStorageStubs(t)
	t.Logf("fail-open LocalStorage stub scan: %d hit(s) across local_*.go", len(hits))
	if len(hits) > 0 {
		t.Errorf("found %d LocalStorage method(s) that silently return a zero-value result with no real "+
			"implementation and no error — indistinguishable from a genuine empty result to any caller. "+
			"Each one must EITHER return a real error (or a documented sentinel) OR carry an inline comment "+
			"justifying why a trivial zero-value return is actually correct here:\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
}
