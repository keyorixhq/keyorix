package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// validationRefusalFamilies are the file-name prefixes of the core families whose
// i18n "ErrorValidation" refusals must be typed (CORE-ERR-FAMILY-7 item 4,
// VALIDATION-TYPED-NOV-1 item 5): groups (group*.go), secrets (secret*.go), catalog
// (catalog*.go), personal access tokens (pat*.go), sharing (sharing*.go, share*.go),
// users (users*.go), secret versions (versions*.go), environment clone (env_clone*.go),
// the self-service account (account*.go), break-glass (break_glass*.go) and access review
// (access_review*.go). Other files that spell the key (setup*.go, invitations.go,
// classification.go, ...) are not scanned yet.
var validationRefusalFamilies = []string{
	"group", "secret", "catalog", "pat", "shar",
	"users", "versions", "env_clone", "account", "break_glass", "access_review",
}

// validationTypingCalls make an error match a sentinel (errors.Is) while keeping its
// text: a refusal built inside one of them is typed. storage.Typed and storage.NotFound
// are matched by their selector name.
var validationTypingCalls = map[string]bool{
	"refuseAs": true, "validationError": true, "validationErrorf": true, "invalidInput": true,
	"invalidGroupRequest": true, "invalidACLRequest": true, "errSecretValidation": true,
	"errSecretInvalidf": true, "errSecretTargetInvalidf": true, "errDependencyInvalidf": true,
	"errVersionDiffInvalidf": true, "secretInvalidInput": true, "Typed": true, "NotFound": true,
	// VALIDATION-TYPED-NOV-1: classifyReadErrorAs(err, ErrValidation, text) types a positive
	// not-found with the sentinel and turns anything else into a storage read fault;
	// refuseBreakGlass(text, kinds...) carries the break-glass kinds; permissionDeniedf is the
	// authorization refusal (ErrPermissionDenied) that access review words with the key.
	"classifyReadErrorAs": true, "refuseBreakGlass": true, "permissionDeniedf": true,
}

// validationTypingLiterals are composite literals that type the refusal they carry:
// policyRefusal{msg: ...} matches ErrPasswordPolicy and ErrValidation (account.go).
var validationTypingLiterals = map[string]bool{"policyRefusal": true}

// untypedValidationRefusals returns the position of every i18n.T("ErrorValidation", ...)
// call that is neither an argument (at any depth) of a validationTypingCalls call nor
// inside the body of one of those helpers, nor a fmt.Errorf that wraps (%w) a package
// sentinel named Err*. Such a refusal reads "Validation error: ..." and no transport can
// classify it without matching that translated text.
func untypedValidationRefusals(fset *token.FileSet, file *ast.File) []string {
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
		call, ok := n.(*ast.CallExpr)
		if !ok || !isI18nValidationKey(call) {
			return true
		}
		for _, anc := range stack[:len(stack)-1] {
			switch a := anc.(type) {
			case *ast.FuncDecl:
				if validationTypingCalls[a.Name.Name] {
					return true
				}
			case *ast.CallExpr:
				if validationTypingCalls[calleeName(a)] || wrapsPackageSentinel(a) {
					return true
				}
			case *ast.CompositeLit:
				if id, ok := a.Type.(*ast.Ident); ok && validationTypingLiterals[id.Name] {
					return true
				}
			}
		}
		bad = append(bad, fset.Position(call.Pos()).String())
		return true
	})
	return bad
}

func isI18nValidationKey(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "T" || len(c.Args) == 0 {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "i18n" {
		return false
	}
	lit, ok := c.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	key, err := strconv.Unquote(lit.Value)
	return err == nil && key == "ErrorValidation"
}

func calleeName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// wrapsPackageSentinel reports a fmt.Errorf whose format has %w and whose arguments
// include an identifier named Err* (ErrPATExpiresInPast, storage.ErrShareNotFound):
// errors.Is already finds that sentinel.
func wrapsPackageSentinel(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Errorf" || len(c.Args) < 2 {
		return false
	}
	if lit, ok := c.Args[0].(*ast.BasicLit); !ok || !strings.Contains(lit.Value, "%w") {
		return false
	}
	for _, a := range c.Args[1:] {
		switch v := a.(type) {
		case *ast.Ident:
			if strings.HasPrefix(v.Name, "Err") {
				return true
			}
		case *ast.SelectorExpr:
			if strings.HasPrefix(v.Sel.Name, "Err") {
				return true
			}
		}
	}
	return false
}

func inValidationRefusalFamily(path string) bool {
	if filepath.Dir(path) != filepath.Join(srcpath.RepoRoot(), filepath.FromSlash(srcpath.CoreDir)) {
		return false
	}
	base := filepath.Base(path)
	for _, p := range validationRefusalFamilies {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	return false
}

// TestEveryValidationRefusalIsTyped is the ErrorValidation sibling of
// TestEveryGrantCeilingRefusalIsTyped: in the groups, secrets, catalog, pat, sharing,
// users, versions, env-clone, account, break-glass and access-review families every refusal worded with the i18n "ErrorValidation" key matches a sentinel
// (the family's own, or ErrValidation), so HTTP and gRPC answer it 400 /
// InvalidArgument by errors.Is and never by the translated text. It walks core family
// files, so it reports through guardrules.Rollout (docs/guard-rollout-contract.md rule 2).
// It does not prove the chosen sentinel is the right family, only that one is there;
// TestErrFamily7_ValidationRefusalsMatchTheirFamily checks the mapping per family.
func TestEveryValidationRefusalIsTyped(t *testing.T) {
	g := guardrules.Rollout(t)
	files, err := srcpath.CoreFamilyGoFiles()
	require.NoError(g, err)
	fset := token.NewFileSet()
	var bad []string
	scanned := 0
	for _, f := range files {
		if !inValidationRefusalFamily(f) {
			continue
		}
		scanned++
		file, err := parser.ParseFile(fset, f, nil, 0)
		require.NoError(g, err)
		bad = append(bad, untypedValidationRefusals(fset, file)...)
	}
	require.Positive(g, scanned, "no family file was scanned: the prefixes or the core dir moved")
	require.Empty(g, bad, "ErrorValidation refusals not built with a typing helper (validationError, invalidGroupRequest, secretInvalidInput, ...)")
}

// The scan fires on the untyped spellings and spares the typed ones.
func TestValidationRefusalScanCalibration(t *testing.T) {
	const src = `package core
import ("errors"; "fmt")
func untypedErrorf() error { return fmt.Errorf("%s: name is required", i18n.T("ErrorValidation", nil)) }
func untypedNew() error    { return errors.New(i18n.T("ErrorValidation", nil)) }
func untypedWrap(err error) error { return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err) }
func typedHelper() error   { return validationError(fmt.Errorf("%s: x", i18n.T("ErrorValidation", nil))) }
func typedGroup() error    { return invalidGroupRequest(fmt.Errorf("%s: x", i18n.T("ErrorValidation", nil))) }
func typedStorage() error  { return storage.Typed(ErrX, fmt.Sprintf("%s: x", i18n.T("ErrorValidation", nil)), nil) }
func typedSentinel() error { return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrPATExpiresInPast) }
func errSecretValidation(cause error) error { return fmt.Errorf("%s: %v", i18n.T("ErrorValidation", nil), cause) }
func typedRead() error     { return classifyReadErrorAs(err, ErrValidation, fmt.Sprintf("%s: unknown role", i18n.T("ErrorValidation", nil))) }
func typedBreakGlass() error { return refuseBreakGlass(fmt.Sprintf("%s: x", i18n.T("ErrorValidation", nil)), ErrBreakGlassInvalidRequest) }
func typedDenied() error   { return permissionDeniedf("%s: x", i18n.T("ErrorValidation", nil)) }
func typedPolicy() error   { return policyRefusal{msg: i18n.T("ErrorValidation", nil) + ": password must be longer"} }
func untypedLiteral() error { return otherRefusal{msg: i18n.T("ErrorValidation", nil) + ": x"} }
func otherKey() error      { return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil)) }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "calibration", src, 0)
	require.NoError(t, err)
	bad := untypedValidationRefusals(fset, file)
	require.Len(t, bad, 4, "only the four untyped spellings fire: %v", bad)
	require.Contains(t, bad[0], ":3:")
	require.Contains(t, bad[1], ":4:")
	require.Contains(t, bad[2], ":5:")
	require.Contains(t, bad[3], ":15:", "a composite literal of a type that does not type its refusal fires")
}
