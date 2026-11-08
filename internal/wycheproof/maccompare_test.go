package wycheproof

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// macName matches identifiers that hold a MAC, signature or tag.
var macName = regexp.MustCompile(`(?i)(^|[a-z0-9_])(mac|hmac|sig|signature|tag)$`)

// macCompareFindings returns "file:line: text" for every non-constant-time
// comparison of a MAC-like value in src (RULES.md section 4).
//
// An operand is named by its identifier or selector (mac, x.Sig), also
// through a slice expression (sig[:], tag[:16]) and through one wrapping
// call: string(x), []byte(x), hex.EncodeToString(x),
// base64.<Encoding>.EncodeToString(x).
//
// What it does NOT see: a MAC copied into a variable whose name does not
// match (got := mac; got == want), index expressions (mac[0]), other
// encoders (fmt.Sprintf("%x", mac)), comparisons inside a helper that takes
// the MAC under another parameter name, and switch statements on a MAC.
func macCompareFindings(fset *token.FileSet, f *ast.File) []string {
	var out []string
	name := func(e ast.Expr) string {
		switch v := e.(type) {
		case *ast.Ident, *ast.SelectorExpr, *ast.SliceExpr:
			return name2(v)
		case *ast.CallExpr:
			// string(x), []byte(x), hex.EncodeToString(x),
			// base64.StdEncoding.EncodeToString(x): look through the call
			if len(v.Args) == 1 {
				switch fn := v.Fun.(type) {
				case *ast.Ident:
					if fn.Name == "string" {
						return name2(v.Args[0])
					}
				case *ast.ArrayType:
					return name2(v.Args[0])
				case *ast.SelectorExpr:
					if fn.Sel.Name == "EncodeToString" {
						return name2(v.Args[0])
					}
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
	case *ast.SliceExpr:
		return name2(v.X)
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

// TestMACComparisonsAreConstantTime is a repo-wide guard over macCompareDirs
// (docs/guard-rollout-contract.md): it reports through guardrules.Rollout and
// is report-only on PRs while docs/guard-rollout.d/TestMACComparisonsAreConstantTime.tsv
// exists. A listed directory that is gone or holds no non-test Go file fails,
// so a moved package cannot drop out of the scan silently.
func TestMACComparisonsAreConstantTime(t *testing.T) {
	g := guardrules.Rollout(t)
	root := srcpath.RepoRoot()
	total := 0
	for _, d := range macCompareDirs {
		files, err := filepath.Glob(filepath.Join(root, d, "*.go"))
		if err != nil {
			g.Fatalf("%s: %v", d, err)
		}
		scanned := 0
		for _, fn := range files {
			if strings.HasSuffix(fn, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, fn, nil, 0)
			if err != nil {
				g.Fatalf("%s: %v", fn, err)
			}
			scanned++
			for _, finding := range macCompareFindings(fset, f) {
				rel := strings.TrimPrefix(finding, root+string(filepath.Separator))
				if _, ok := macCompareAllow[allowKey(rel)]; ok {
					continue
				}
				g.Errorf("non-constant-time comparison of a MAC-like value: %s", rel)
			}
		}
		if scanned == 0 {
			g.Errorf("macCompareDirs: %s has no non-test Go files (moved or renamed? update the list)", d)
		}
		total += scanned
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
