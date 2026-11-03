package encryption

// key_lock_hint_callers_guard_test.go -- MSG-ACCURACY-1 (#3742, REVIEW-3933-DEEP-1
// F2). A key-lock refusal used to tell the operator to stop a server for every
// cause: a missing key directory and permission denied included. The PR fixed
// eight callers and the review found three more in server/admin. This guard
// covers the family: every production caller of AcquireExclusiveKeyLock /
// AcquireSharedKeyLock may blame another holder only through
// WithLockContentionHint (or encryptionops' withLockContentionHint wrapper),
// which adds the hint on real contention (EWOULDBLOCK) only.
//
// # What it recognises
//
//   - The call `x.AcquireExclusiveKeyLock()` / `x.AcquireSharedKeyLock()` in a
//     non-test .go file of the root module (nested modules such as cli/ and
//     operator/ are skipped; neither calls these methods).
//   - Form IF: `if err := x.Acquire...KeyLock(); err != nil { ... }`. Every
//     string literal in the if-body that blames a holder (blameWording) must
//     sit inside the arguments of a contention-hint call.
//   - Form RETURN: `return x.Acquire...KeyLock()` inside internal/encryption,
//     a pass-through wrapper (AuthEncryption's); its callers are checked.
//   - Any other form (the error assigned and checked later, discarded, passed
//     on) is a finding, so a new shape cannot slip past unrecognised.
//
// # What it does not recognise
//
//   - Blame wording built outside a string literal in the if-body (a constant
//     or a helper that formats its own message). It is a phrase guard.
//   - Callers of AcquireKeyFileReadLock (a different, blocking-free read lock
//     whose callers report their own errors).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

var (
	keyLockAcquireMethods = map[string]bool{"AcquireExclusiveKeyLock": true, "AcquireSharedKeyLock": true}
	contentionHintFuncs   = map[string]bool{"WithLockContentionHint": true, "withLockContentionHint": true}
	blameWording          = regexp.MustCompile(`(?i)\b(?:live|running|the) server\b|another process|in-progress|concurrent|is using|stop (?:it|the)\b`)
)

func isKeyLockAcquire(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && keyLockAcquireMethods[sel.Sel.Name]
}

func isContentionHintCall(call *ast.CallExpr) bool {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return contentionHintFuncs[f.Name]
	case *ast.SelectorExpr:
		return contentionHintFuncs[f.Sel.Name]
	}
	return false
}

// keyLockCallerFindings returns one message per key-lock caller in file that
// blames a holder outside a contention-hint call or uses an unrecognised form.
// rel is the file's slash path relative to the repository root.
func keyLockCallerFindings(fset *token.FileSet, file *ast.File, rel string) []string {
	var out []string
	handled := map[ast.Expr]bool{}
	at := func(n ast.Node) string { return fmt.Sprintf("%s:%d", rel, fset.Position(n.Pos()).Line) }

	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.IfStmt:
			as, ok := s.Init.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || !isKeyLockAcquire(as.Rhs[0]) {
				return true
			}
			handled[as.Rhs[0]] = true
			ast.Inspect(s.Body, func(b ast.Node) bool {
				if call, ok := b.(*ast.CallExpr); ok && isContentionHintCall(call) {
					return false
				}
				lit, ok := b.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					v = lit.Value
				}
				if m := blameWording.FindString(v); m != "" {
					out = append(out, fmt.Sprintf("%s: key-lock refusal says %q for every cause; pass the hint through encryption.WithLockContentionHint so a missing directory or permission error is not blamed on another process", at(lit), m))
				}
				return true
			})
		case *ast.ReturnStmt:
			if len(s.Results) == 1 && isKeyLockAcquire(s.Results[0]) && strings.HasPrefix(rel, "internal/encryption/") {
				handled[s.Results[0]] = true
			}
		}
		return true
	})
	ast.Inspect(file, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && isKeyLockAcquire(e) && !handled[e] {
			out = append(out, fmt.Sprintf("%s: unrecognised key-lock call form; use `if err := x.%s(); err != nil {...}` so this guard can check the refusal text", at(e), e.(*ast.CallExpr).Fun.(*ast.SelectorExpr).Sel.Name))
		}
		return true
	})
	return out
}

func parseGuardSource(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fset, f
}

// TestKeyLockCallerFindings_Calibration plants the shapes the guard must flag
// and the ones it must accept, so a green repo run is not a blind one.
func TestKeyLockCallerFindings_Calibration(t *testing.T) {
	cases := []struct {
		name, rel, body string
		want            int
	}{
		{"unconditional server blame (the pre-fix server/admin shape)", "server/admin/x.go",
			`if err := svc.AcquireExclusiveKeyLock(); err != nil { return fmt.Errorf("failed to acquire the encryption key lock (stop the server first): %w", err) }`, 1},
		{"unconditional another-process blame", "server/admin/x.go",
			`if err := svc.AcquireExclusiveKeyLock(); err != nil { return fmt.Errorf("lock (another process is using it): %w", err) }`, 1},
		{"hint through WithLockContentionHint", "server/admin/x.go",
			`if err := svc.AcquireExclusiveKeyLock(); err != nil { return fmt.Errorf("lock: %w", encryption.WithLockContentionHint(err, "stop the server first")) }`, 0},
		{"hint through the encryptionops wrapper", "internal/encryptionops/x.go",
			`if err := s.AcquireSharedKeyLock(); err != nil { s.Shutdown(); return withLockContentionHint(err, "a live server is using this key directory") }`, 0},
		{"neutral refusal", "server/x.go",
			`if err := svc.AcquireExclusiveKeyLock(); err != nil { return fmt.Errorf("failed to acquire the encryption key lock: %w", err) }`, 0},
		{"error checked later", "server/admin/x.go",
			`err := svc.AcquireExclusiveKeyLock(); if err != nil { return err }`, 1},
		{"pass-through wrapper inside internal/encryption", "internal/encryption/x.go",
			`return ae.service.AcquireSharedKeyLock()`, 0},
		{"pass-through outside internal/encryption", "server/admin/x.go",
			`return svc.AcquireSharedKeyLock()`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset, f := parseGuardSource(t, "package p\nfunc f() error {\n"+tc.body+"\nreturn nil\n}\n")
			got := keyLockCallerFindings(fset, f, tc.rel)
			if len(got) != tc.want {
				t.Fatalf("want %d finding(s), got %d: %v", tc.want, len(got), got)
			}
		})
	}
}

// TestKeyLockRefusalsBlameAHolderOnlyOnContention walks every production Go
// file of the root module.
func TestKeyLockRefusalsBlameAHolderOnlyOnContention(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()
	fset := token.NewFileSet()
	var findings []string
	seen := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walking this repository's own sources
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), "KeyLock()") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		findings = append(findings, keyLockCallerFindings(fset, f, rel)...)
		ast.Inspect(f, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok && isKeyLockAcquire(e) {
				seen++
			}
			return true
		})
		return nil
	})
	if err != nil {
		g.Fatalf("walk %s: %v", root, err)
	}
	// 2026-11-03: 17 call sites (internal/encryption, internal/encryptionops,
	// server/admin, server). A walk that finds none is broken, not clean.
	if seen < 10 {
		g.Fatalf("found only %d key-lock call sites; the walk is not seeing the repository", seen)
	}
	t.Logf("checked %d key-lock call sites", seen)
	for _, f := range findings {
		g.Errorf("%s", f)
	}
}
