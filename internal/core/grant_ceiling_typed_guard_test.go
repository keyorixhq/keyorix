package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// grantCeilingPhrase opens every refusal of the grant ceiling (a granter that does not
// hold the permissions of the role it grants). HTTP and gRPC answer it by
// errors.Is(err, ErrPermissionDenied); the text is not a contract.
const grantCeilingPhrase = "cannot grant this role"

// untypedGrantCeilingRefusals returns the position of every string literal containing
// grantCeilingPhrase that is not an argument of permissionDeniedf / markPermissionDenied
// (the helpers that make the error match ErrPermissionDenied). A bare fmt.Errorf or
// errors.New with that text would be a ceiling refusal no transport can classify.
func untypedGrantCeilingRefusals(fset *token.FileSet, file *ast.File) []string {
	typed := map[string]bool{"permissionDeniedf": true, "markPermissionDenied": true}
	var (
		stack []ast.Node
		bad   []string
	)
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || !strings.Contains(lit.Value, grantCeilingPhrase) {
			return true
		}
		for _, anc := range stack {
			if c, ok := anc.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && typed[id.Name] {
					return true
				}
			}
		}
		bad = append(bad, fset.Position(lit.Pos()).String())
		return true
	})
	return bad
}

// TestEveryGrantCeilingRefusalIsTyped is the sibling of
// TestEveryErrorPermissionDeniedRefusalIsTyped for the refusal that one does not see:
// it is worded in English ("cannot grant this role: ..."), not from the i18n
// ErrorPermissionDenied key. It walks every core-family file, so it reports through
// guardrules.Rollout (docs/guard-rollout-contract.md rule 2).
func TestEveryGrantCeilingRefusalIsTyped(t *testing.T) {
	g := guardrules.Rollout(t)
	files, err := srcpath.CoreFamilyGoFiles()
	require.NoError(g, err)
	fset := token.NewFileSet()
	var bad []string
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		require.NoError(g, err)
		bad = append(bad, untypedGrantCeilingRefusals(fset, file)...)
	}
	require.Empty(g, bad, "grant-ceiling refusals not built with permissionDeniedf / markPermissionDenied")
}

// The scan fires on an untyped refusal and spares the typed ones.
func TestGrantCeilingScanCalibration(t *testing.T) {
	const src = `package core
import ("errors"; "fmt")
func untypedErrorf() error { return fmt.Errorf("cannot grant this role: you do not hold %q", "x") }
func untypedNew() error    { return errors.New("cannot grant this role") }
func typedf() error        { return permissionDeniedf("cannot grant this role: you do not hold %q", "x") }
func typedMark() error     { return markPermissionDenied(fmt.Errorf("cannot grant this role")) }
func unrelated() error     { return fmt.Errorf("cannot grant this share") }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "calibration", src, 0)
	require.NoError(t, err)
	bad := untypedGrantCeilingRefusals(fset, file)
	require.Len(t, bad, 2, "only the fmt.Errorf and errors.New spellings are untyped: %v", bad)
	require.Contains(t, bad[0], ":3:")
	require.Contains(t, bad[1], ":4:")
}
