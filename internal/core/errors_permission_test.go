package core

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrPermissionDenied_SpecificSentinelsMatchIt(t *testing.T) {
	specific := []error{
		ErrSoDPermissionDenied, ErrRiskExceptionPermissionDenied, ErrMachinePrivilegeCeilingDenied,
		ErrShareActionNotElevated, ErrShareNotOwner, ErrShareOwnerNotMember, ErrShareRecipientNotMember,
		ErrShareGroupNotInProject, ErrOwnedShareListDenied, ErrShareRecipientSearchDenied,
	}
	for i, s := range specific {
		require.ErrorIs(t, fmt.Errorf("outer: %w", s), ErrPermissionDenied, "%v", s)
		for j, other := range specific {
			if i != j {
				require.NotErrorIs(t, s, other, "%v must stay distinguishable from %v", s, other)
			}
		}
	}
	// The classified wrappers keep matching their own kind and gain the generic one.
	sod := wrapSoDPermissionDenied(errors.New("x"))
	require.ErrorIs(t, sod, ErrSoDPermissionDenied)
	require.ErrorIs(t, sod, ErrPermissionDenied)
	require.NotErrorIs(t, sod, ErrSoDValidation)
	risk := wrapRiskExceptionPermissionDenied(errors.New("x"))
	require.ErrorIs(t, risk, ErrRiskExceptionPermissionDenied)
	require.ErrorIs(t, risk, ErrPermissionDenied)
}

func TestPermissionDeniedf_TextUnchangedAndOnlyRefusalsMatch(t *testing.T) {
	err := permissionDeniedf("%s: %s", "Доступ запрещён", "insufficient permissions")
	require.Equal(t, "Доступ запрещён: insufficient permissions", err.Error())
	require.ErrorIs(t, fmt.Errorf("outer: %w", err), ErrPermissionDenied)

	// An OS error that merely says "permission denied" is not an authorization refusal.
	osErr := fmt.Errorf("open /etc/x: %w", os.ErrPermission)
	require.Contains(t, osErr.Error(), "permission denied")
	require.NotErrorIs(t, osErr, ErrPermissionDenied)
	require.NotErrorIs(t, errors.New("permission denied"), ErrPermissionDenied)
	require.NoError(t, markPermissionDenied(nil))
}

func TestBreakGlassPermissionRefusalsMatchErrPermissionDenied(t *testing.T) {
	for _, kind := range []error{ErrBreakGlassDisabled, ErrBreakGlassNotProjectMember} {
		err := refuseBreakGlass("x", kind, ErrPermissionDenied)
		require.ErrorIs(t, err, kind)
		require.ErrorIs(t, err, ErrPermissionDenied)
	}
}

// TestEveryErrorPermissionDeniedRefusalIsTyped: a core refusal built from the
// i18n "ErrorPermissionDenied" text must be built through a helper that makes it
// match ErrPermissionDenied, so no handler needs to match the (translated) text.
func TestEveryErrorPermissionDeniedRefusalIsTyped(t *testing.T) {
	allowed := map[string]bool{
		"permissionDeniedf": true, "markPermissionDenied": true,
		"wrapSoDPermissionDenied": true, "wrapRiskExceptionPermissionDenied": true,
		"shareRefusal": true,
	}
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var bad []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		require.NoError(t, err)
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok || !isI18nT(call, "ErrorPermissionDenied") {
				return true
			}
			for _, anc := range stack {
				// shareRefusal wraps a sentinel that itself matches ErrPermissionDenied.
				if fd, ok := anc.(*ast.FuncDecl); ok && fd.Name.Name == "shareRefusal" {
					return true
				}
				if c, ok := anc.(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && allowed[id.Name] {
						return true
					}
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "refuseBreakGlass" && mentionsIdent(c, "ErrPermissionDenied") {
						return true
					}
				}
			}
			bad = append(bad, fset.Position(call.Pos()).String())
			return true
		})
	}
	require.Empty(t, bad, "i18n ErrorPermissionDenied refusals not typed with ErrPermissionDenied")
}

func isI18nT(call *ast.CallExpr, key string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "T" || len(call.Args) == 0 {
		return false
	}
	if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "i18n" {
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	return ok && lit.Value == `"`+key+`"`
}

func mentionsIdent(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}
