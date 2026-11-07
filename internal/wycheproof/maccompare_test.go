package wycheproof

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// macName matches identifiers that hold a MAC, signature, tag or digest.
var macName = regexp.MustCompile(`(?i)(^|[a-z0-9_])(mac|hmac|sig|signature|tag)$`)

// macCompareFindings returns "file:line: text" for every non-constant-time
// comparison of a MAC-like value in src (RULES.md section 4).
func macCompareFindings(fset *token.FileSet, f *ast.File) []string {
	var out []string
	name := func(e ast.Expr) string {
		switch v := e.(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			return v.Sel.Name
		case *ast.CallExpr:
			// string(x), []byte(x), hex.EncodeToString(x): look through the conversion
			if len(v.Args) == 1 {
				switch fn := v.Fun.(type) {
				case *ast.Ident:
					if fn.Name == "string" {
						return name2(v.Args[0])
					}
				case *ast.ArrayType:
					return name2(v.Args[0])
				}
			}
		}
		return ""
	}
	constant := func(e ast.Expr) bool {
		switch v := e.(type) {
		case *ast.BasicLit:
			return true
		case *ast.Ident:
			return v.Name == "nil" || v.Name == "true" || v.Name == "false" || strings.HasPrefix(v.Name, "Err") || strings.HasPrefix(v.Name, "err")
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok && (id.Name == "len" || id.Name == "cap") {
				return true
			}
		case *ast.SelectorExpr:
			return strings.HasPrefix(v.Sel.Name, "Err")
		}
		return false
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BinaryExpr:
			if v.Op != token.EQL && v.Op != token.NEQ {
				return true
			}
			if constant(v.X) || constant(v.Y) {
				return true
			}
			if macName.MatchString(name(v.X)) || macName.MatchString(name(v.Y)) {
				out = append(out, fset.Position(v.Pos()).String()+": "+v.Op.String()+" on "+name(v.X)+" / "+name(v.Y))
			}
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			full := pkg.Name + "." + sel.Sel.Name
			if full != "bytes.Equal" && full != "strings.EqualFold" && full != "reflect.DeepEqual" && full != "strings.Compare" && full != "bytes.Compare" {
				return true
			}
			for _, a := range v.Args {
				if macName.MatchString(name(a)) {
					out = append(out, fset.Position(v.Pos()).String()+": "+full+" on "+name(a))
				}
			}
		}
		return true
	})
	return out
}

func name2(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

func findingsInSource(t testing.TB, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return macCompareFindings(fset, f)
}

// macCompareDirs are the packages whose non-test files compare MACs,
// signatures or tags (relative to the repository root).
var macCompareDirs = []string{
	"internal/auditverify", "internal/core", "internal/pqwrap", "internal/backupfmt",
	"internal/crypto", "internal/recoverykey", "internal/encryption", "internal/encryption/aead",
	"internal/storage/store", "internal/notary", "internal/integrity", "internal/solewriter",
	"pkg/trust", "pkg/licenseverify", "pkg/bundleverify", "server/middleware", "server/admin",
}

// macCompareAllow lists reviewed findings that are not MAC comparisons.
// Key: "<file base>:<identifier pair>". Each entry carries the reason.
var macCompareAllow = map[string]string{
	"local_notification_channel_url_migration.go:== on tag / NotificationChannelURLTagPlaintext": "storage format marker, not an authentication tag",
	"backup_legacy_url_guard.go:== on tag / NotificationChannelURLTagAbsent":                     "storage format marker, not an authentication tag",
}

func TestMACComparisonsAreConstantTime(t *testing.T) {
	root := srcpath.RepoRoot()
	total := 0
	for _, d := range macCompareDirs {
		files, _ := filepath.Glob(filepath.Join(root, d, "*.go"))
		for _, fn := range files {
			if strings.HasSuffix(fn, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, fn, nil, 0)
			if err != nil {
				t.Fatalf("%s: %v", fn, err)
			}
			total++
			for _, finding := range macCompareFindings(fset, f) {
				rel := strings.TrimPrefix(finding, root+string(filepath.Separator))
				if _, ok := macCompareAllow[allowKey(rel)]; ok {
					continue
				}
				t.Errorf("non-constant-time comparison of a MAC-like value: %s", rel)
			}
		}
	}
	t.Logf("scanned %d files in %d packages", total, len(macCompareDirs))
}

func allowKey(finding string) string {
	// "dir/file.go:line:col: <text>" -> "file.go:<text>"
	loc, text, ok := strings.Cut(finding, ": ")
	if !ok {
		return finding
	}
	return filepath.Base(strings.SplitN(loc, ":", 2)[0]) + ":" + text
}
