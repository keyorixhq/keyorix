package encryption

// sweep_completeness_test.go — regression test for backlog #425's structural
// concern: SweepAllTables (sweep.go/sweep_auth.go) is a hand-maintained list of
// individual sweepXxx calls, and nothing prevents a future developer from adding
// a new DEK-encrypted column to internal/storage/models WITHOUT also adding a
// corresponding sweep — silently re-introducing the exact shape of #422 (a
// DEK-rotation sweep gap that caused permanent, irrecoverable data loss for the
// tables it missed).
//
// There is no way to make Go statically verify "every DEK-encrypted column has a
// sweep" — encryption happens at the application layer, not via any type the
// compiler could check. Instead, this test parses every non-test .go file in
// internal/storage/models via go/ast (NOT a hardcoded list of model types, so a
// brand-new model struct is picked up automatically — only the discovered FIELD
// still has to match the naming convention below) for struct fields matching the
// naming convention every one of today's 8 DEK-encrypted columns follows: type
// []byte, name either "Encrypted*" or "*Enc". It then diffs that discovered set
// against expectedSweptFields, a hand-maintained map mirroring exactly what
// SweepAllTables sweeps today.
//
// This only catches a NEW column that follows the existing naming convention —
// it can't catch one that doesn't, or a coincidentally-named non-encrypted field
// (there are none today; see the exhaustive grep this test's PR description
// documents). Within that scope, though, it turns "a future developer forgot to
// add a sweep" from a silent, discovered-in-production data-loss bug into a
// failing test, at test time, with an actionable message pointing at exactly
// which field is unaccounted for.
import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// modelField identifies one struct field in internal/storage/models.
type modelField struct {
	Struct string
	Field  string
}

func (f modelField) String() string { return f.Struct + "." + f.Field }

// expectedSweptFields mirrors exactly what SweepAllTables (sweep.go's
// sweepSecretVersions + sweep_auth.go's sweepSessions/sweepAPITokens/
// sweepAPIClients/sweepPasswordResets/sweepMFASecrets/sweepDynamicSecretConfigs/
// sweepDynamicSecretLeases) re-encrypts today. Keep this in lockstep with
// SweepAllTables — that's the entire point of this test.
var expectedSweptFields = map[modelField]bool{
	{"SecretVersion", "EncryptedValue"}:     true,
	{"Session", "EncryptedSessionToken"}:    true,
	{"APIToken", "EncryptedToken"}:          true,
	{"APIClient", "EncryptedClientSecret"}:  true,
	{"PasswordReset", "EncryptedToken"}:     true,
	{"MFASecret", "SecretEnc"}:              true,
	{"DynamicSecretConfig", "AdminDSNEnc"}:  true,
	{"DynamicSecretLease", "CredentialEnc"}: true,
}

// TestSweepCompleteness_EveryEncryptedModelFieldHasASweep is the regression test
// described above.
func TestSweepCompleteness_EveryEncryptedModelFieldHasASweep(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate internal/storage/models relative to this test file")
	}
	modelsDir := filepath.Join(filepath.Dir(thisFile), "..", "storage", "models")

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, modelsDir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", modelsDir, err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("no packages found under %s — did the models package move?", modelsDir)
	}

	discovered := map[modelField]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					return true
				}
				for _, f := range st.Fields.List {
					if !isByteSliceType(f.Type) {
						continue
					}
					for _, name := range f.Names {
						if looksLikeEncryptedFieldName(name.Name) {
							discovered[modelField{ts.Name.Name, name.Name}] = true
						}
					}
				}
				return true
			})
		}
	}

	if len(discovered) == 0 {
		t.Fatal("discovered zero Encrypted*/*Enc []byte fields in internal/storage/models — the AST walk is almost certainly broken (models.go alone has several), not that encryption was removed")
	}

	var missing []modelField
	for f := range discovered {
		if !expectedSweptFields[f] {
			missing = append(missing, f)
		}
	}
	var stale []modelField
	for f := range expectedSweptFields {
		if !discovered[f] {
			stale = append(stale, f)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].String() < missing[j].String() })
	sort.Slice(stale, func(i, j int) bool { return stale[i].String() < stale[j].String() })

	if len(missing) > 0 {
		t.Errorf("found DEK-encrypted-looking field(s) in internal/storage/models NOT accounted for by this test's expectedSweptFields map: %v\n"+
			"Verify each one is actually re-encrypted by SweepAllTables (internal/encryption/sweep.go + sweep_auth.go) — if it's a genuinely new "+
			"DEK-encrypted column, add a sweepXxx call for it there (see #422 for what happens if you don't), then add it to expectedSweptFields "+
			"here. If it's a false positive (a []byte field that happens to match the naming convention but isn't DEK-encrypted), narrow the "+
			"looksLikeEncryptedFieldName heuristic instead.", missing)
	}
	if len(stale) > 0 {
		t.Errorf("expectedSweptFields lists field(s) no longer found (by name+type) in internal/storage/models — update this test's expected map: %v", stale)
	}
}

// isByteSliceType reports whether expr is exactly `[]byte` (an unsized array/slice
// of the builtin identifier "byte").
func isByteSliceType(expr ast.Expr) bool {
	arr, ok := expr.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	ident, ok := arr.Elt.(*ast.Ident)
	return ok && ident.Name == "byte"
}

// looksLikeEncryptedFieldName reports whether name follows the DEK-encrypted
// column naming convention every one of today's 8 tracked fields uses:
// EncryptedValue, EncryptedSessionToken, EncryptedToken (x2), EncryptedClientSecret,
// SecretEnc, AdminDSNEnc, CredentialEnc.
func looksLikeEncryptedFieldName(name string) bool {
	return strings.HasPrefix(name, "Encrypted") || strings.HasSuffix(name, "Enc")
}
