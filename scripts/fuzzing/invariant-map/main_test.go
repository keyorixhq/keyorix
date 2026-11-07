package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The fixture stores its INVARIANTS.md / INVARIANTS.d under a ".fx" suffix so
// the repository's own invariant-doc guard does not parse the planted gaps as
// real invariants; copyFixture restores the real names in a temp dir.
const fixtureSrc = "testdata/fixture"

func copyFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(fixtureSrc, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixtureSrc, p)
		rel = strings.ReplaceAll(rel, ".fx", "")
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func analyzeFixture(t *testing.T) *Report {
	t.Helper()
	rep, err := Analyze(copyFixture(t), false)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func find(t *testing.T, rep *Report, id string) Invariant {
	t.Helper()
	for _, i := range rep.Invariants {
		if i.ID == id {
			return i
		}
	}
	t.Fatalf("invariant %s not in report", id)
	return Invariant{}
}

func hasFlag(i Invariant, f string) bool {
	return slices.Contains(i.Flags, f)
}

// The fixture plants one invariant per outcome; every one must be reported.
func TestFixtureClassification(t *testing.T) {
	rep := analyzeFixture(t)
	if rep.Summary.Invariants != 9 {
		t.Fatalf("want 9 distinct invariants, got %d", rep.Summary.Invariants)
	}
	cases := []struct {
		id, class, strength string
	}{
		{"INV-A-01", ClassFuzz, "strong"}, // named in a fuzz target doc comment and targets.d
		{"INV-A-02", ClassTest, ""},       // test reference
		{"INV-A-03", ClassDocOnly, ""},    // planted gap
		{"INV-A-04", ClassDocOnly, ""},    // only check is gone
		{"INV-A-06", ClassTest, ""},       // wipe test
		{"INV-A-07", ClassFuzz, "file"},   // helper in a fuzz test file
		{"INV-A-fragment-slug-rule", ClassDocOnly, ""},
	}
	for _, c := range cases {
		got := find(t, rep, c.id)
		if got.Class != c.class || got.FuzzStrength != c.strength {
			t.Errorf("%s: class=%s strength=%q, want %s %q", c.id, got.Class, got.FuzzStrength, c.class, c.strength)
		}
	}
}

func TestFixtureStaleDuplicateAndPrefix(t *testing.T) {
	rep := analyzeFixture(t)
	if st := find(t, rep, "INV-A-04").StaleChecks; len(st) != 1 || st[0] != "TestTokenExpiryGone" {
		t.Errorf("INV-A-04 stale checks = %v", st)
	}
	if !hasFlag(find(t, rep, "INV-A-05"), "duplicate-id") {
		t.Error("INV-A-05 should be flagged duplicate-id")
	}
	if !hasFlag(find(t, rep, "INV-B-01"), "prefix-mismatch") {
		t.Error("INV-B-01 should be flagged prefix-mismatch")
	}
	if rep.Summary.WithStale != 1 || rep.Summary.Duplicates != 1 {
		t.Errorf("summary stale=%d dup=%d", rep.Summary.WithStale, rep.Summary.Duplicates)
	}
	kinds := map[string]bool{}
	for _, c := range rep.Inconsistency {
		kinds[c.Kind] = true
	}
	for _, k := range []string{"duplicate-id", "prefix-mismatch", "possible-rename"} {
		if !kinds[k] {
			t.Errorf("missing inconsistency kind %s (got %v)", k, kinds)
		}
	}
}

func TestFixtureUnknownReference(t *testing.T) {
	rep := analyzeFixture(t)
	// The "INV-A-NN" format placeholder in the doc is not a reference.
	if len(rep.UnknownRefs) != 1 {
		t.Fatalf("unknown refs = %+v", rep.UnknownRefs)
	}
	typo := rep.UnknownRefs[0]
	if typo.ID != "INV-A-91" || !typo.InCode || typo.Suggestion != "INV-A-01" {
		t.Errorf("unexpected typo ref %+v", typo)
	}
}

func TestFixtureCheckFindsPlantedGaps(t *testing.T) {
	rep := analyzeFixture(t)
	problems := strings.Join(Check(rep, nil, true, false), "\n")
	for _, want := range []string{
		"undefined invariant ID INV-A-91",
		"invariant INV-A-03 ",
		"INV-A-04 names a check that no longer exists: TestTokenExpiryGone",
	} {
		if !strings.Contains(problems, want) {
			t.Errorf("check output lacks %q:\n%s", want, problems)
		}
	}
	// INV-A-07 and the fragment are explicitly UNGUARDED; INV-A-04 has Guard text.
	for _, no := range []string{"INV-A-07", "INV-A-fragment-slug-rule", "invariant INV-A-04 (", "INV-A-02"} {
		if strings.Contains(problems, no+" has no check") || (no == "INV-A-02" && strings.Contains(problems, no)) {
			t.Errorf("unexpected problem for %s:\n%s", no, problems)
		}
	}
}

func TestAllowlistSuppresses(t *testing.T) {
	rep := analyzeFixture(t)
	rules := []Rule{{AllowUnknownRef, "INV-A-9*"}, {AllowNoCheck, "INV-A-03"}, {AllowStale, "INV-A-04"}}
	if p := Check(rep, rules, true, false); len(p) != 0 {
		t.Errorf("allowlist should silence everything, got %v", p)
	}
	if p := Check(rep, nil, false, false); len(p) != 2 {
		t.Errorf("-no-stale should drop only the stale finding, got %v", p)
	}
}

func TestLoadAllowlistRejectsBadLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "al.txt")
	if err := os.WriteFile(p, []byte("# c\nno-check INV-X-1 # ok\nbogus INV-X-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAllowlist(p); err == nil {
		t.Fatal("want error for unknown kind")
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	a, b := analyzeFixture(t), analyzeFixture(t)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) || Markdown(a) != Markdown(b) {
		t.Fatal("two runs over the same tree differ")
	}
}

func TestRunCheckExitCodes(t *testing.T) {
	fixture := copyFixture(t)
	var out, errw bytes.Buffer
	if code := run([]string{"-root", fixture, "-check", "-include-self"}, &out, &errw); code != 1 {
		t.Fatalf("fixture check exit = %d, want 1\n%s%s", code, out.String(), errw.String())
	}
	dir := t.TempDir()
	js, md := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.md")
	out.Reset()
	if code := run([]string{"-root", fixture, "-include-self", "-json", js, "-md", md}, &out, &errw); code != 0 {
		t.Fatalf("report exit = %d", code)
	}
	for _, f := range []string{js, md} {
		if st, err := os.Stat(f); err != nil || st.Size() == 0 {
			t.Errorf("%s not written", f)
		}
	}
}

// TestRepoCheck is the CI guard: the real tree must pass `-check`.
func TestRepoCheck(t *testing.T) {
	root, err := findRoot()
	if err != nil {
		t.Skip(err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "INVARIANTS.md")); err != nil {
		t.Skip("not the keyorix tree")
	}
	rep, err := Analyze(root, true)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := loadAllowlist(filepath.Join(root, selfDir, "allowlist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if p := Check(rep, rules, true, false); len(p) > 0 {
		t.Fatalf("invariant-map -check failed:\n%s", strings.Join(p, "\n"))
	}
}
