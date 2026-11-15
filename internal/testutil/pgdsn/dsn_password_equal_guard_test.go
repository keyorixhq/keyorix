package pgdsn

// dsn_password_equal_guard_test.go -- a failing require.Equal / assert.Equal
// prints both operands, so one that compares a DSN password leaks the real
// password (it comes from KEYORIX_TEST_PG_DSN) into the test log (#3392).
// Compare with require.True(t, a == b, "passwords differ") instead.
//
// What it recognizes: a call to Equal, Equalf, EqualValues, Exactly, NotEqual
// or NotEqualf on a package named require or assert, in a *dsn*_test.go file,
// with an argument that names a password: an identifier or selector whose name
// contains "password", "passwd" or "secret", or starts or ends with "pw".
// String literals are not read, and a password held in an
// innocently named variable is not seen.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

var equalFuncs = map[string]bool{
	"Equal": true, "Equalf": true, "EqualValues": true, "Exactly": true, "NotEqual": true, "NotEqualf": true,
}

func namesPassword(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "password") || strings.Contains(l, "passwd") || strings.Contains(l, "secret") ||
		strings.HasPrefix(l, "pw") || strings.HasSuffix(l, "pw")
}

// passwordEqualCalls returns "file:line" for each Equal-family call in src
// that takes a password-named argument.
func passwordEqualCalls(filename string, src any) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !equalFuncs[sel.Sel.Name] {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || (pkg.Name != "require" && pkg.Name != "assert") {
			return true
		}
		hit := false
		for _, arg := range call.Args {
			ast.Inspect(arg, func(m ast.Node) bool {
				switch m := m.(type) {
				case *ast.Ident:
					if namesPassword(m.Name) {
						hit = true
					}
				case *ast.CallExpr:
					// The name of a called function is not a value (a bool
					// from dsnHasPassword(x)); its arguments still are.
					if id, ok := m.Fun.(*ast.Ident); ok && namesPassword(id.Name) {
						for _, a := range m.Args {
							ast.Inspect(a, func(k ast.Node) bool {
								if id, ok := k.(*ast.Ident); ok && namesPassword(id.Name) {
									hit = true
								}
								return !hit
							})
						}
						return false
					}
				}
				return !hit
			})
		}
		if hit {
			out = append(out, fset.Position(call.Pos()).String())
		}
		return true
	})
	return out, nil
}

func TestNoEqualOnPasswordsInDSNTests(t *testing.T) {
	root := repoRoot(t)
	var bad []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".scratch", ".gopath", "vendor", "tmp":
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, "_test.go") || !strings.Contains(name, "dsn") {
			return nil
		}
		hits, err := passwordEqualCalls(path, nil)
		if err != nil {
			return err
		}
		for _, h := range hits {
			rel, _ := filepath.Rel(root, h)
			if rel == "" || strings.HasPrefix(rel, "..") {
				rel = h
			}
			bad = append(bad, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(bad) > 0 {
		t.Errorf("require/assert Equal on a password prints it when it fails; use require.True(t, a == b, \"passwords differ\"):\n  %s",
			strings.Join(bad, "\n  "))
	}
}

func TestPasswordEqualGuardCalibration(t *testing.T) {
	const offender = `package x
import ("testing"; "github.com/stretchr/testify/require")
func TestX(t *testing.T) {
	require.Equal(t, want.Password, got.Password)
}`
	const clean = `package x
import ("testing"; "github.com/stretchr/testify/require")
func TestX(t *testing.T) {
	require.True(t, want.Password == got.Password, "passwords differ")
	require.Equal(t, want.Host, got.Host, "password host")
}`
	const boolFromCall = `package x
import ("testing"; "github.com/stretchr/testify/assert")
func TestX(t *testing.T) {
	assert.Equal(t, want, dsnHasPassword(dsn), dsn)
}`
	if hits, err := passwordEqualCalls("x_test.go", boolFromCall); err != nil || len(hits) != 0 {
		t.Fatalf("a bool from a password-named function: hits=%v err=%v, want none", hits, err)
	}
	if hits, err := passwordEqualCalls("x_test.go", offender); err != nil || len(hits) != 1 {
		t.Fatalf("offender: hits=%v err=%v, want exactly one hit", hits, err)
	}
	if hits, err := passwordEqualCalls("x_test.go", clean); err != nil || len(hits) != 0 {
		t.Fatalf("clean: hits=%v err=%v, want none", hits, err)
	}
}
