package main

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

const mod = "example.test/m"

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func ask(t *testing.T, files map[string]string, lines map[string][]int) *response {
	t.Helper()
	resp, err := run(request{Root: writeTree(t, files), Module: mod, Files: lines})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestUnusedConstHasNoReferences(t *testing.T) {
	resp := ask(t, map[string]string{
		"a/a.go": "package a\n\nconst unused = 3\n\nfunc F() int { return 1 }\n",
	}, map[string][]int{"a/a.go": {3}})
	got := resp.Lines["a/a.go"]["3"]
	if got.Kind != "decl" || !reflect.DeepEqual(got.Names, []string{"unused"}) || got.Impure {
		t.Fatalf("line 3 = %+v", got)
	}
	if refs := resp.Refs["a/a.go#unused"]; len(refs) != 0 {
		t.Fatalf("an unreferenced const must have no sites, got %+v", refs)
	}
}

func TestSamePackageReferenceIsASite(t *testing.T) {
	resp := ask(t, map[string]string{
		"a/a.go":      "package a\n\nconst limit = 3\n",
		"a/b.go":      "package a\n\nfunc F() int {\n\treturn limit\n}\n",
		"a/c_test.go": "package a\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) { _ = limit }\n",
	}, map[string][]int{"a/a.go": {3}})
	refs := resp.Refs["a/a.go#limit"]
	want := []Site{{File: "a/b.go", Line: 4}, {File: "a/c_test.go", Line: 5, Test: true}}
	if len(refs) != 2 || !contains(refs, want[0]) || !contains(refs, want[1]) {
		t.Fatalf("sites = %+v, want %+v", refs, want)
	}
}

func contains(ss []Site, s Site) bool {
	return slices.Contains(ss, s)
}

func TestCrossPackageReferenceThroughImportAlias(t *testing.T) {
	resp := ask(t, map[string]string{
		"a/a.go":     "package a\n\nconst Limit = 3\n",
		"b/b.go":     "package b\n\nimport aa \"" + mod + "/a\"\n\nvar _ = aa.Limit\n",
		"c/c.go":     "package c\n\nimport \"" + mod + "/a\"\n\nfunc g() int { return a.Limit }\n",
		"d/other.go": "package d\n\nvar a struct{ Limit int }\n\nvar _ = a.Limit\n", // no import of the package: not a site
	}, map[string][]int{"a/a.go": {3}})
	refs := resp.Refs["a/a.go#Limit"]
	if len(refs) != 2 || !contains(refs, Site{File: "b/b.go", Line: 5}) || !contains(refs, Site{File: "c/c.go", Line: 5}) {
		t.Fatalf("sites = %+v", refs)
	}
}

func TestIotaGroupLinksEverySpec(t *testing.T) {
	src := "package a\n\nconst (\n\tA = iota\n\tB\n\tC\n)\n\nconst (\n\tX = 1\n\tY = 2\n)\n"
	resp := ask(t, map[string]string{"a/a.go": src}, map[string][]int{"a/a.go": {5, 3, 10}})
	if got := resp.Lines["a/a.go"]["5"].Names; !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("a line in an iota group stands for every spec of it, got %v", got)
	}
	if got := resp.Lines["a/a.go"]["3"].Names; !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("the `const (` line stands for every spec, got %v", got)
	}
	if got := resp.Lines["a/a.go"]["10"].Names; !reflect.DeepEqual(got, []string{"X"}) {
		t.Fatalf("independent specs are separate, got %v", got)
	}
}

func TestVarPurity(t *testing.T) {
	src := "package a\n\nimport (\n\t\"errors\"\n\t\"regexp\"\n)\n\nvar ErrX = errors.New(\"x\")\n\nvar re = regexp.MustCompile(`(`)\n\nvar n = compute()\n\nvar _ = register()\n\nvar plain = map[string]int{\"a\": 1}\n\nfunc compute() int { return 1 }\n\nfunc register() int { return 1 }\n"
	resp := ask(t, map[string]string{"a/a.go": src}, map[string][]int{"a/a.go": {8, 10, 12, 14, 16}})
	l := resp.Lines["a/a.go"]
	for ln, impure := range map[string]bool{"8": false, "10": true, "12": true, "14": true, "16": false} {
		if l[ln].Kind != "decl" || l[ln].Impure != impure {
			t.Errorf("line %s = %+v, want impure=%v", ln, l[ln], impure)
		}
	}
}

func TestFuncHeaderSpansMultilineSignature(t *testing.T) {
	src := "package a\n\nfunc F(\n\ta int,\n\tb int,\n) (int, error) {\n\tx := a + b\n\treturn x, nil\n}\n"
	resp := ask(t, map[string]string{"a/a.go": src}, map[string][]int{"a/a.go": {3, 4, 6, 7}})
	l := resp.Lines["a/a.go"]
	for _, ln := range []string{"3", "4", "6"} {
		if l[ln].Kind != "funcheader" || !reflect.DeepEqual(l[ln].Body, []int{6, 9}) {
			t.Errorf("line %s = %+v, want funcheader body 6-9", ln, l[ln])
		}
	}
	if l["7"].Kind != "funcbody" {
		t.Errorf("a body line is not a header: %+v", l["7"])
	}
}

func TestFuncBodyLinesAreStrictlyInsideTheBraces(t *testing.T) {
	// 1 package a / 3 func f() { / 4 x := 1 / 5 y := 2 / 6 } / 8 func g() { return }
	src := "package a\n\nfunc f() {\n\tx := 1\n\ty := 2\n}\n\nfunc g() int { return 1 }\n"
	l := ask(t, map[string]string{"a/a.go": src}, map[string][]int{"a/a.go": {3, 4, 5, 6, 7, 8}}).Lines["a/a.go"]
	for _, ln := range []string{"4", "5"} {
		if l[ln].Kind != "funcbody" || !reflect.DeepEqual(l[ln].Body, []int{3, 6}) {
			t.Errorf("line %s = %+v, want funcbody body 3-6", ln, l[ln])
		}
	}
	// the `{` line is the header, the `}` line and the blank after it are not interior,
	// and a one-line function is a header only
	if l["3"].Kind != "funcheader" || l["6"].Kind != "other" || l["7"].Kind != "other" || l["8"].Kind != "funcheader" {
		t.Errorf("edges wrong: %+v", l)
	}
}

func TestRecursiveTypeDoesNotReferenceItself(t *testing.T) {
	src := "package a\n\ntype node struct {\n\tnext *node\n}\n"
	resp := ask(t, map[string]string{"a/a.go": src}, map[string][]int{"a/a.go": {3, 4}})
	if refs := resp.Refs["a/a.go#node"]; len(refs) != 0 {
		t.Fatalf("a type naming itself inside its own spec is not a use, got %+v", refs)
	}
}

func TestUnparsableRequestedFileIsReported(t *testing.T) {
	resp := ask(t, map[string]string{"a/a.go": "package a\n\nconst = \n"}, map[string][]int{"a/a.go": {3}})
	if len(resp.ParseErrors) != 1 || len(resp.Lines) != 0 {
		t.Fatalf("a file that does not parse must give no line info, got %+v", resp)
	}
}
