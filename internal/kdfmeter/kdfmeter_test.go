package kdfmeter_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/kdfmeter"
)

const (
	kdfmeterImportPath = "github.com/keyorixhq/keyorix/internal/kdfmeter"
	bcryptImportPath   = "golang.org/x/crypto/bcrypt"
)

// TestKDFMeter_CountsGenerateAndCompare is the red/green proof that the seam
// counts. With an observer installed, each GenerateFromPassword yields exactly
// one OpGenerate and each CompareHashAndPassword exactly one OpCompare; with the
// observer uninstalled, the counters do not move (zero behaviour change when off).
func TestKDFMeter_CountsGenerateAndCompare(t *testing.T) {
	var gen, cmp int
	prev := kdfmeter.SetObserver(func(op kdfmeter.Op) {
		switch op {
		case kdfmeter.OpGenerate:
			gen++
		case kdfmeter.OpCompare:
			cmp++
		}
	})
	t.Cleanup(func() { kdfmeter.SetObserver(prev) })

	hash, err := kdfmeter.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := kdfmeter.CompareHashAndPassword(hash, []byte("pw")); err != nil {
		t.Fatalf("compare (correct): %v", err)
	}
	// A wrong password still costs exactly one compare — the property the
	// enumeration oracle leans on.
	_ = kdfmeter.CompareHashAndPassword(hash, []byte("wrong"))

	if gen != 1 {
		t.Fatalf("OpGenerate count = %d, want 1", gen)
	}
	if cmp != 2 {
		t.Fatalf("OpCompare count = %d, want 2", cmp)
	}

	// Uninstall: counters must freeze. This is the "zero behaviour change when
	// off" half — a guard nobody has watched stay still is not a guard.
	kdfmeter.SetObserver(nil)
	if _, err := kdfmeter.GenerateFromPassword([]byte("pw"), bcrypt.MinCost); err != nil {
		t.Fatalf("generate (observer off): %v", err)
	}
	_ = kdfmeter.CompareHashAndPassword(hash, []byte("pw"))
	if gen != 1 || cmp != 2 {
		t.Fatalf("counters moved with observer off: gen=%d cmp=%d", gen, cmp)
	}
}

// TestKDFMeter_BehaviourIdenticalToBcrypt confirms the wrapper is a pass-through:
// the hash it produces verifies, and a wrong password fails, exactly as the raw
// library would — so routing production through it changes nothing observable.
func TestKDFMeter_BehaviourIdenticalToBcrypt(t *testing.T) {
	hash, err := kdfmeter.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("correct horse")); err != nil {
		t.Fatalf("raw bcrypt must verify a kdfmeter-produced hash: %v", err)
	}
	if err := kdfmeter.CompareHashAndPassword(hash, []byte("correct horse")); err != nil {
		t.Fatalf("kdfmeter must verify its own hash: %v", err)
	}
	if err := kdfmeter.CompareHashAndPassword(hash, []byte("wrong")); err == nil {
		t.Fatal("wrong password must fail")
	}
}

// bcryptAllowlist is the complete set of non-test Go files that may import
// golang.org/x/crypto/bcrypt directly, keyed by repo-relative slash path. Every
// other production file must go through internal/kdfmeter, or the KDF-count oracle
// (internal/core/kdf_enumeration_oracle_fuzz_test.go) cannot see its KDF work.
// Each entry carries the reason it is exempt; TestBcryptImportedOnlyThroughKDFMeter
// also fails if an entry stops importing bcrypt, so the list cannot go stale.
var bcryptAllowlist = map[string]string{
	"internal/kdfmeter/kdfmeter.go": "the metered seam itself",
	"internal/core/bcrypt_cost.go": "builds the timing-equaliser sentinel hash at init and in " +
		"SetBcryptCostForTesting; not a credential operation, and metering it would count work " +
		"outside any logical operation",
	"scripts/timing-constant-time/main.go": "manual one-off timing-measurement tool; not a credential " +
		"path and not wired into CI",
}

// TestBcryptImportedOnlyThroughKDFMeter fails if any non-_test.go file outside
// bcryptAllowlist imports golang.org/x/crypto/bcrypt. It reads the import
// declarations, not the file text, so an aliased import cannot hide and a mention in
// a comment or string cannot trip it.
//
// It does NOT verify that every KDF call goes through the seam in a file that does
// not import bcrypt (e.g. a different KDF such as scrypt or argon2, which the meter
// does not wrap at all), nor that a metered call is made exactly once per logical
// operation: that is the oracle's job, per path it exercises.
func TestBcryptImportedOnlyThroughKDFMeter(t *testing.T) {
	root := repoRoot(t)
	var offenders []string
	seenAllowed := map[string]bool{}
	for _, rel := range productionGoFiles(t, root) {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		imports, err := importsOf(rel, b)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		if !imports[bcryptImportPath] {
			continue
		}
		if _, ok := bcryptAllowlist[rel]; ok {
			seenAllowed[rel] = true
			continue
		}
		offenders = append(offenders, rel)
	}
	if len(offenders) > 0 {
		t.Fatalf("production file(s) import %s directly and bypass the KDF meter; use "+
			"internal/kdfmeter, or add the file to bcryptAllowlist with a reason: %s",
			bcryptImportPath, strings.Join(offenders, ", "))
	}
	for rel := range bcryptAllowlist {
		if !seenAllowed[rel] {
			t.Errorf("bcryptAllowlist entry %q no longer imports bcrypt (or no longer exists): remove it", rel)
		}
	}
}

// TestBcryptImportGuard_Calibration watches the import check fail and pass on
// synthetic sources: a guard nobody has seen go red is not a guard.
func TestBcryptImportGuard_Calibration(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"plain import", "package p\nimport \"golang.org/x/crypto/bcrypt\"\n", true},
		{"aliased import", "package p\nimport bc \"golang.org/x/crypto/bcrypt\"\n", true},
		{"grouped import", "package p\nimport (\n\t\"fmt\"\n\t\"golang.org/x/crypto/bcrypt\"\n)\n", true},
		{"blank import", "package p\nimport _ \"golang.org/x/crypto/bcrypt\"\n", true},
		{"only through the seam", "package p\nimport \"" + kdfmeterImportPath + "\"\n", false},
		{"path only in a comment", "package p\n// golang.org/x/crypto/bcrypt\nimport \"fmt\"\n", false},
		{"path only in a string", "package p\nvar s = \"golang.org/x/crypto/bcrypt\"\n", false},
	}
	for _, tc := range cases {
		imports, err := importsOf("calibration.go", []byte(tc.src))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		if got := imports[bcryptImportPath]; got != tc.want {
			t.Errorf("%s: imports bcrypt = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestKDFMeterSetObserver_NoProductionCallers fails the build if any non-_test.go
// file references kdfmeter.SetObserver. Enablement is test-only: the only
// legitimate caller is the resguard KDFMeter, a normal (non-_test.go) file kept
// test-only by TestResguardImportedOnlyFromTests and excluded here by package path.
// This is the machine-checked guard that keeps the seam zero-cost in production.
//
// The check resolves the file's own import of internal/kdfmeter, so an aliased
// import, a dot import, a method-value reference (f := kdfmeter.SetObserver) and a
// call from inside package kdfmeter itself are all caught. It does NOT see a
// reference built through reflection or go:linkname.
func TestKDFMeterSetObserver_NoProductionCallers(t *testing.T) {
	root := repoRoot(t)
	var offenders []string
	for _, rel := range productionGoFiles(t, root) {
		// Excluded BY PACKAGE PATH, not by call shape, so the exclusion is a checkable
		// constant and stays sound if the installer moves between files in that package.
		if strings.HasPrefix(rel, "internal/fuzzutil/resguard/") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		// The identifier cannot appear in a Go file without this substring (Go
		// identifiers have no escapes), so skipping the parse is sound and keeps
		// the repo-wide walk cheap.
		if !strings.Contains(string(b), "SetObserver") {
			continue
		}
		hits, err := setObserverReferences(rel, b)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		if len(hits) > 0 {
			offenders = append(offenders, rel)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("kdfmeter.SetObserver is test-only but is referenced from production file(s): %s",
			strings.Join(offenders, ", "))
	}
}

// TestSetObserverGuard_Calibration watches the reference check fail on every shape
// it claims to catch and pass on the clean shapes, so neither direction is assumed.
func TestSetObserverGuard_Calibration(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"qualified call", "package p\nimport \"" + kdfmeterImportPath + "\"\nfunc f() { kdfmeter.SetObserver(nil) }\n", true},
		{"aliased import", "package p\nimport km \"" + kdfmeterImportPath + "\"\nfunc f() { km.SetObserver(nil) }\n", true},
		{"dot import", "package p\nimport . \"" + kdfmeterImportPath + "\"\nfunc f() { SetObserver(nil) }\n", true},
		{"method value", "package p\nimport \"" + kdfmeterImportPath + "\"\nvar f = kdfmeter.SetObserver\n", true},
		{"call inside the package", "package kdfmeter\nfunc g() { SetObserver(nil) }\n", true},
		{"declaration only", "package kdfmeter\nfunc SetObserver(fn func(Op)) func(Op) { return nil }\n", false},
		{"counting call only", "package p\nimport \"" + kdfmeterImportPath + "\"\nfunc f() { _ = kdfmeter.CompareHashAndPassword(nil, nil) }\n", false},
		{"name in comment and string", "package p\nimport \"" + kdfmeterImportPath + "\"\n// kdfmeter.SetObserver is test-only\nvar s = \"kdfmeter.SetObserver\"\n", false},
		{"unrelated SetObserver", "package p\nimport \"other\"\nfunc f() { other.SetObserver(nil) }\n", false},
	}
	for _, tc := range cases {
		hits, err := setObserverReferences("calibration.go", []byte(tc.src))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		if got := len(hits) > 0; got != tc.want {
			t.Errorf("%s: flagged = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// importsOf returns the set of import paths declared by one Go source file.
func importsOf(filename string, src []byte) (map[string]bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, err
		}
		out[p] = true
	}
	return out, nil
}

// setObserverReferences returns every reference to kdfmeter's SetObserver in one
// Go source file. A reference is a selector on the name the file imports
// internal/kdfmeter under, a bare identifier in a file that dot-imports it, or a
// bare identifier inside package kdfmeter other than its own declaration.
func setObserverReferences(filename string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	local, dot := "", false
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, err
		}
		if p != kdfmeterImportPath {
			continue
		}
		switch {
		case imp.Name == nil:
			local = "kdfmeter"
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name == "_":
			// A blank import brings no identifiers into scope.
		default:
			local = imp.Name.Name
		}
	}
	inPackage := f.Name.Name == "kdfmeter"
	declared := map[*ast.Ident]bool{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "SetObserver" {
			declared[fd.Name] = true
		}
	}
	var hits []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && x.Sel.Name == "SetObserver" {
				hits = append(hits, fset.Position(x.Pos()).String())
			}
		case *ast.Ident:
			if (dot || inPackage) && x.Name == "SetObserver" && !declared[x] {
				hits = append(hits, fset.Position(x.Pos()).String())
			}
		}
		return true
	})
	return hits, nil
}

// productionGoFiles returns the repo-relative slash paths of every non-_test.go Go
// file under root, sorted. It skips .git, vendor, node_modules, .scratch and the
// separate operator/ module (its own go.mod; guard-inputs row `!operator/**`).
func productionGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", ".scratch":
				return filepath.SkipDir
			}
			if rel == "operator" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(files)
	return files
}

// repoRoot walks up from the package dir to the module root (the dir with go.mod).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from package dir")
		}
		dir = parent
	}
}
