package auditverify

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImportPrefixes are the packages that WROTE the audit chain this
// package independently re-verifies (design §4: "a verifier that reuses the
// server's own storage layer... proves less"). internal/notary is the one
// documented exception — reused as-is, not duplicated (design §4).
var forbiddenImportPrefixes = []string{
	"github.com/keyorixhq/keyorix/internal/core",
	"github.com/keyorixhq/keyorix/internal/storage",
	"gorm.io/",
}

// TestDependencyGuard_NoCoreOrStorageImports proves — by parsing this
// package's own non-test source files, not by inspecting go.mod (which
// would only prove the MODULE could theoretically import them) — that
// nothing in internal/auditverify imports internal/core,
// internal/storage(/...), or GORM. This is the mechanism design §4's
// independence requirement rests on: a bug or backdoor in the code that
// wrote the chain must be invisible to this guard failing, not just to a
// reviewer remembering to check.
//
// Deliberately reads *_test.go files too but SKIPS them: this file's own
// sibling differential test legitimately imports internal/core and
// internal/storage/store to build known-good fixtures via the real writer —
// that is the intended, documented shape of the parity test (design §9),
// not a violation of the production package's independence.
func TestDependencyGuard_NoCoreOrStorageImports(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package files: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no .go files found in internal/auditverify — glob pattern or cwd is wrong")
	}

	checked := 0
	fset := token.NewFileSet()
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		checked++
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			for _, forbidden := range forbiddenImportPrefixes {
				if importPath == forbidden || strings.HasPrefix(importPath, forbidden) {
					t.Errorf("%s imports %q, which internal/auditverify must never import — "+
						"this package must independently re-derive everything it checks, not "+
						"reuse the code that wrote the chain (design §4)", path, importPath)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("every .go file in this directory was a _test.go file — the guard checked nothing")
	}
}
