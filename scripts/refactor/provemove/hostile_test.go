package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Hostile cases from the PR #3695 deep review (F6-F8): each one reported
// PURE MOVE before. A tree is a map of repository-relative file -> content.

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func provemoveTrees(t *testing.T, base, head map[string]string, dirs string) (int, string) {
	t.Helper()
	return runProvemove(t, "-base", writeTree(t, base), "-head", writeTree(t, head), "-dirs", dirs)
}

const pkgX = "package x\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {}\n\nfunc helper() int { return 1 }\n"

// F6: a -dirs typo read nothing and printed "PURE MOVE: 0 declarations identical".
func TestProvemove_NoDeclarationsIsAnError(t *testing.T) {
	tree := map[string]string{"internal/x/x.go": "package x\n\nfunc F() {}\n"}
	code, out := provemoveTrees(t, tree, tree, "internal/typo")
	if code != 2 || strings.Contains(out, "PURE MOVE") {
		t.Fatalf("no declarations read: exit %d, output %q, want exit 2 and no PURE MOVE", code, out)
	}
	// The dir exists in both trees but holds no Go declaration.
	empty := map[string]string{"internal/x/README.md": "notes\n", "internal/x/doc.go": "// Package x.\npackage x\n"}
	if code, out := provemoveTrees(t, empty, empty, "internal/x"); code != 2 || strings.Contains(out, "PURE MOVE") {
		t.Fatalf("dirs with no declarations: exit %d, output %q, want exit 2", code, out)
	}
}

// F6: one real dir plus a typo still proved the real dir only.
func TestProvemove_DirMissingFromBothTreesIsAnError(t *testing.T) {
	tree := map[string]string{"internal/x/x.go": "package x\n\nfunc F() {}\n"}
	code, out := provemoveTrees(t, tree, tree, "internal/x,internal/typo")
	if code != 2 || strings.Contains(out, "PURE MOVE") {
		t.Fatalf("a -dirs entry in neither tree: exit %d, output %q, want exit 2", code, out)
	}
	// A dir present in only one tree is a real move (new or emptied package).
	head := map[string]string{"internal/x/x.go": "package x\n", "internal/y/y.go": "package x\n\nfunc F() {}\n"}
	if code, out := provemoveTrees(t, tree, head, "internal/x,internal/y"); code != 0 {
		t.Fatalf("a dir that exists in one tree only must be allowed: exit %d, output %q", code, out)
	}
}

// F7: a test moved into a non-test file silently stops running.
func TestProvemove_TestMovedToNonTestFileIsRed(t *testing.T) {
	base := map[string]string{"internal/x/x_test.go": pkgX}
	head := map[string]string{"internal/x/x_helpers.go": pkgX}
	code, out := provemoveTrees(t, base, head, "internal/x")
	if code != 1 || !strings.Contains(out, "MISSING in head: x|func:TestA [test]") || !strings.Contains(out, "ADDED in head: x|func:TestA\n") {
		t.Fatalf("x_test.go -> x_helpers.go: exit %d, output %q", code, out)
	}
	// Moving between two test files is still a pure move.
	head = map[string]string{"internal/x/y_test.go": pkgX}
	if code, out := provemoveTrees(t, base, head, "internal/x"); code != 0 {
		t.Fatalf("x_test.go -> y_test.go: exit %d, output %q", code, out)
	}
}

// F7: the GOOS/GOARCH file-name suffix is a build constraint.
func TestProvemove_GOOSSuffixChangeIsRed(t *testing.T) {
	src := "package x\n\nfunc F() {}\n"
	for _, tc := range []struct{ from, to string }{
		{"internal/x/f_linux.go", "internal/x/f.go"},
		{"internal/x/f_amd64.go", "internal/x/f_arm64.go"},
		{"internal/x/f_linux_amd64.go", "internal/x/f_linux.go"},
		{"internal/x/f_windows_test.go", "internal/x/f_test.go"},
	} {
		code, out := provemoveTrees(t, map[string]string{tc.from: src}, map[string]string{tc.to: src}, "internal/x")
		if code != 1 || !strings.Contains(out, "MISSING in head") {
			t.Errorf("%s -> %s: exit %d, output %q", tc.from, tc.to, code, out)
		}
	}
	// A suffix that is not a GOOS/GOARCH name is just a file name.
	code, out := provemoveTrees(t, map[string]string{"internal/x/f_helpers.go": src}, map[string]string{"internal/x/f_other.go": src}, "internal/x")
	if code != 0 {
		t.Errorf("f_helpers.go -> f_other.go: exit %d, output %q", code, out)
	}
	// Same suffix in another file: pure.
	code, out = provemoveTrees(t, map[string]string{"internal/x/a_linux.go": src}, map[string]string{"internal/x/b_linux.go": src}, "internal/x")
	if code != 0 {
		t.Errorf("a_linux.go -> b_linux.go: exit %d, output %q", code, out)
	}
}

// F8: //go: directives are comments, and comments were dropped.
func TestProvemove_GoDirectiveChangeIsRed(t *testing.T) {
	for name, tc := range map[string]struct{ base, head string }{
		"embed target": {
			"package x\n\nimport _ \"embed\"\n\n//go:embed a.txt\nvar data string\n",
			"package x\n\nimport _ \"embed\"\n\n//go:embed b.txt\nvar data string\n",
		},
		"embed in a group": {
			"package x\n\nimport \"embed\"\n\nvar (\n\t//go:embed a\n\tfsys embed.FS\n)\n",
			"package x\n\nimport \"embed\"\n\nvar (\n\t//go:embed b\n\tfsys embed.FS\n)\n",
		},
		"linkname target, attached": {
			"package x\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\nfunc now() int64\n",
			"package x\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.walltime\nfunc now() int64\n",
		},
		"linkname target, floating": {
			"package x\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\n\nfunc now() int64\n",
			"package x\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.walltime\n\nfunc now() int64\n",
		},
		"directive dropped": {
			"package x\n\n//go:noinline\nfunc F() {}\n",
			"package x\n\nfunc F() {}\n",
		},
		"build constraint": {
			"//go:build linux\n\npackage x\n\nfunc F() {}\n",
			"//go:build windows\n\npackage x\n\nfunc F() {}\n",
		},
		"build constraint dropped": {
			"//go:build integration\n\npackage x\n\nfunc F() {}\n",
			"package x\n\nfunc F() {}\n",
		},
	} {
		code, out := provemoveTrees(t, map[string]string{"internal/x/a.go": tc.base}, map[string]string{"internal/x/b.go": tc.head}, "internal/x")
		if code != 1 || !strings.Contains(out, "CHANGED body") {
			t.Errorf("%s: exit %d, output %q, want CHANGED body", name, code, out)
		}
	}
	// The same directive and constraint, moved to another file: pure.
	src := "//go:build linux\n\npackage x\n\nimport _ \"embed\"\n\n//go:embed a.txt\nvar data string\n\n//go:noinline\nfunc F() {}\n"
	if code, out := provemoveTrees(t, map[string]string{"internal/x/a.go": src}, map[string]string{"internal/x/b.go": src}, "internal/x"); code != 0 {
		t.Errorf("unchanged directives in a moved file: exit %d, output %q", code, out)
	}
}

// Hostile cases from the PR #3695 re-review (N1-N3): each one reported
// PURE MOVE, or could not tell a real change from the expected diff, before.

// N1: a const spec with no value of its own repeats the previous spec's type
// and expressions with its own iota, so reordering the group swaps values.
func TestProvemove_IotaReorderIsRed(t *testing.T) {
	for name, tc := range map[string]struct {
		base, head string
		changed    []string
	}{
		"implicit specs": {
			"package x\n\nconst (\n\tRoleViewer = iota\n\tRoleEditor\n\tRoleAdmin\n)\n",
			"package x\n\nconst (\n\tRoleViewer = iota\n\tRoleAdmin\n\tRoleEditor\n)\n",
			[]string{"x|const:RoleAdmin", "x|const:RoleEditor"},
		},
		"explicit iota": {
			"package x\n\nconst (\n\tA = iota\n\tB = iota\n)\n",
			"package x\n\nconst (\n\tB = iota\n\tA = iota\n)\n",
			[]string{"x|const:A", "x|const:B"},
		},
		"inherited type, spec swapped between groups": {
			"package x\n\ntype (\n\tK int\n\tL int\n)\n\nconst (\n\tA K = iota\n\tB\n)\n\nconst (\n\tC L = iota\n\tD\n)\n",
			"package x\n\ntype (\n\tK int\n\tL int\n)\n\nconst (\n\tA K = iota\n\tD\n)\n\nconst (\n\tC L = iota\n\tB\n)\n",
			[]string{"x|const:B", "x|const:D"},
		},
	} {
		code, out := provemoveTrees(t, map[string]string{"internal/x/a.go": tc.base}, map[string]string{"internal/x/b.go": tc.head}, "internal/x")
		if code != 1 {
			t.Errorf("%s: exit %d, output %q, want exit 1", name, code, out)
		}
		for _, k := range tc.changed {
			if !strings.Contains(out, "CHANGED body: "+k+"\n") {
				t.Errorf("%s: output %q, want CHANGED body: %s", name, out, k)
			}
		}
	}
	// The same group moved to another file, and an implicit spec written out
	// with the same value: pure.
	group := "package x\n\nconst (\n\tA = iota\n\tB\n\tC = \"c\"\n\tD\n)\n"
	if code, out := provemoveTrees(t, map[string]string{"internal/x/a.go": group}, map[string]string{"internal/x/b.go": group}, "internal/x"); code != 0 {
		t.Errorf("an unchanged iota group in another file: exit %d, output %q", code, out)
	}
	spelled := "package x\n\nconst (\n\tA = iota\n\tB = iota\n\tC = \"c\"\n\tD = \"c\"\n)\n"
	if code, out := provemoveTrees(t, map[string]string{"internal/x/a.go": group}, map[string]string{"internal/x/b.go": spelled}, "internal/x"); code != 0 {
		t.Errorf("implicit specs spelled out with the same values: exit %d, output %q", code, out)
	}
}

// N2: go build and go test ignore files whose name starts with "_" or ".".
func TestProvemove_IgnoredFileNameIsRed(t *testing.T) {
	for _, to := range []string{"internal/x/_x_test.go", "internal/x/.x_test.go", "internal/x/_x.go"} {
		code, out := provemoveTrees(t, map[string]string{"internal/x/x_test.go": pkgX}, map[string]string{to: pkgX}, "internal/x")
		if code != 1 || !strings.Contains(out, "MISSING in head: x|func:TestA [test]") || !strings.Contains(out, "ADDED in head: x|func:TestA [ignored]") {
			t.Errorf("x_test.go -> %s: exit %d, output %q, want MISSING [test] and ADDED [ignored]", to, code, out)
		}
	}
	// Reviving an ignored file is a change too.
	if code, out := provemoveTrees(t, map[string]string{"internal/x/_x.go": pkgX}, map[string]string{"internal/x/x.go": pkgX}, "internal/x"); code != 1 {
		t.Errorf("_x.go -> x.go: exit %d, output %q", code, out)
	}
}

// N3: ADR-121 decision 3 moves a declaration to a leaf and leaves an alias in
// core. -alias leaf=core proves that shape, and a body change in the leaf
// (int -> int64) must not hide behind the alias.
func TestProvemove_LeafExtractionWithAliases(t *testing.T) {
	const (
		coreSrc  = "package core\n\ntype Level int\n\nfunc Score(l Level) int { return int(l) }\n\nfunc stays() {}\n"
		leafSrc  = "package leaf\n\ntype Level int\n\nfunc Score(l Level) int { return int(l) }\n"
		aliasSrc = "package core\n\nimport \"github.com/keyorixhq/keyorix/internal/leaf\"\n\ntype Level = leaf.Level\n\nvar Score = leaf.Score\n\nfunc stays() {}\n"
	)
	base := writeTree(t, map[string]string{"internal/core/score.go": coreSrc})
	extract := func(head map[string]string, extra ...string) (int, string) {
		t.Helper()
		args := append([]string{"-base", base, "-head", writeTree(t, head), "-dirs", "internal/core,internal/leaf"}, extra...)
		return runProvemove(t, args...)
	}
	pure := map[string]string{"internal/leaf/score.go": leafSrc, "internal/core/score.go": aliasSrc}
	code, out := extract(pure, "-alias", "leaf=core")
	want := "ALIAS in head: core|type:Level = leaf.Level\nALIAS in head: core|var:Score = leaf.Score\n" +
		"PURE MOVE: 3 declarations identical, 2 alias(es) to moved declarations\n"
	if code != 0 || out != want {
		t.Fatalf("leaf extraction with aliases: exit %d, output %q, want %q", code, out, want)
	}
	// B2: the moved type changes underneath its alias.
	changed := map[string]string{"internal/leaf/score.go": strings.Replace(leafSrc, "type Level int", "type Level int64", 1), "internal/core/score.go": aliasSrc}
	code, out2 := extract(changed, "-alias", "leaf=core")
	if code != 1 || out2 == out || !strings.Contains(out2, "CHANGED body: core|type:Level\n") {
		t.Fatalf("int -> int64 behind the alias: exit %d, output %q, want CHANGED body: core|type:Level", code, out2)
	}
	// An alias whose target did not move (it is new in the leaf) is not an alias of a moved declaration.
	added := map[string]string{"internal/leaf/score.go": leafSrc + "\nfunc New() {}\n",
		"internal/core/score.go": aliasSrc + "\nvar New = leaf.New\n"}
	if code, out := extract(added, "-alias", "leaf=core"); code != 1 || !strings.Contains(out, "ADDED in head: core|func:New\n") {
		t.Fatalf("a new leaf declaration behind an alias: exit %d, output %q, want ADDED", code, out)
	}
	// An alias pointing at nothing in the leaf.
	dangling := map[string]string{"internal/leaf/score.go": "package leaf\n\ntype Level int\n", "internal/core/score.go": aliasSrc}
	if code, out := extract(dangling, "-alias", "leaf=core"); code != 1 || !strings.Contains(out, "UNRESOLVED alias in head: core|var:Score = leaf.Score") ||
		!strings.Contains(out, "MISSING in head: core|func:Score\n") {
		t.Fatalf("an alias to a declaration the leaf does not have: exit %d, output %q", code, out)
	}
	// A leaf extracted before base: the alias is in both trees, nothing to report.
	already := writeTree(t, pure)
	if code, out := runProvemove(t, "-base", already, "-head", already, "-dirs", "internal/core,internal/leaf", "-alias", "leaf=core"); code != 0 ||
		out != "PURE MOVE: 3 declarations identical\n" {
		t.Fatalf("an alias present in both trees: exit %d, output %q", code, out)
	}
	// Without -alias the aliases are differences, as before.
	if code, _ := extract(pure); code != 1 {
		t.Fatalf("aliases without -alias: exit %d, want 1", code)
	}
}
