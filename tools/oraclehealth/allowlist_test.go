package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTSV writes lines joined by newlines to a temp file and returns its path.
func writeTSV(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "allow.tsv")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodRow = "FuzzA\tpkg/x.go\tFoo\tbound-const\t5\t6\tequivalent\treads a byte position no predicate observes"

// TestLoadAllowlist_ParsesAndMatches is the loader's green path: a valid row loads
// and matches a mutation whose orig/new collapse to the stored form, even when the
// real source fragment is multi-line and indented (the whitespace-collapse match).
func TestLoadAllowlist_ParsesAndMatches(t *testing.T) {
	body := "# header comment\n" +
		"target\tfile\tfunc\top\torig\tnew\tclass\treason\n" +
		goodRow + "\n" +
		"FuzzB\tpkg/y.go\tBar\tdrop-error-guard\tif err != nil { return err }\t{}\tdead\tnot reached by this target\n"
	allow, err := loadAllowlist(writeTSV(t, body))
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	if len(allow) != 2 {
		t.Fatalf("want 2 entries (header + comment skipped), got %d", len(allow))
	}

	// Exact match.
	if _, ok := matchAllow(allow, "FuzzA", Mutation{File: "pkg/x.go", Func: "Foo", Op: "bound-const", Orig: "5", New: "6"}); !ok {
		t.Error("exact survivor did not match its allowlist row")
	}
	// Whitespace-collapse match: a multi-line, re-indented guard body still matches
	// the single-line TSV form.
	multiline := Mutation{File: "pkg/y.go", Func: "Bar", Op: "drop-error-guard",
		Orig: "if err != nil {\n\t\treturn err\n\t}", New: "{}"}
	if _, ok := matchAllow(allow, "FuzzB", multiline); !ok {
		t.Error("multi-line guard body did not match its collapsed allowlist row")
	}
	// A different target must NOT match (the key includes the target).
	if _, ok := matchAllow(allow, "FuzzOther", Mutation{File: "pkg/x.go", Func: "Foo", Op: "bound-const", Orig: "5", New: "6"}); ok {
		t.Error("a survivor under a different target was wrongly allowlisted")
	}
	// A different replacement must NOT match (the key includes new).
	if _, ok := matchAllow(allow, "FuzzA", Mutation{File: "pkg/x.go", Func: "Foo", Op: "bound-const", Orig: "5", New: "0"}); ok {
		t.Error("a survivor with a different replacement was wrongly allowlisted")
	}
}

// TestLoadAllowlist_RejectsDishonestRows is the red path: the loader refuses a row
// with a bad class or an empty reason, so the file cannot silently carry an
// unjustified silence. These are the two ways an entry stops being a traceable claim.
func TestLoadAllowlist_RejectsDishonestRows(t *testing.T) {
	cases := map[string]string{
		"bad class":    "FuzzA\tpkg/x.go\tFoo\tbound-const\t5\t6\tmaybe\treason here",
		"empty reason": "FuzzA\tpkg/x.go\tFoo\tbound-const\t5\t6\tequivalent\t",
		"too few cols": "FuzzA\tpkg/x.go\tFoo\tbound-const\t5\t6\tequivalent",
	}
	for name, row := range cases {
		if _, err := loadAllowlist(writeTSV(t, row)); err == nil {
			t.Errorf("%s: loadAllowlist accepted a row it should reject", name)
		}
	}
}

// TestLoadAllowlist_EmptyPath returns an empty, usable map (not an error) so a run
// without -allowlist behaves as if nothing is suppressed.
func TestLoadAllowlist_EmptyPath(t *testing.T) {
	allow, err := loadAllowlist("")
	if err != nil {
		t.Fatalf("empty path should not error: %v", err)
	}
	if _, ok := matchAllow(allow, "FuzzA", Mutation{}); ok {
		t.Error("empty allowlist matched a mutation")
	}
}
