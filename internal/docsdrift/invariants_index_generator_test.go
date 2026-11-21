package docsdrift

// invariants_index_generator_test.go — calibration for
// scripts/gen-invariants-index.sh on a fixture tree: the counting rules of
// docs/INVARIANTS.md "Maintaining this index" (column-0 bullets plus
// INVARIANTS.d/ fragments, UNGUARDED per bullet or fragment and not a raw
// grep -c, the separate fuzzkit/ module excluded), byte-order rows, text
// outside the markers untouched, --check, and the refusals on a broken marker
// pair. TestInvariantsIndexBlockIsGenerated is the same script on the real tree.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeInvFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readInvFixture(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// invFixtureRows returns the "label inv guarded unguarded" of every package row
// between the markers, in document order.
func invFixtureRows(t *testing.T, doc string) []string {
	t.Helper()
	var rows []string
	for _, line := range strings.Split(doc, "\n") {
		if m := invIndexRowRE.FindStringSubmatch(line); m != nil {
			rows = append(rows, strings.Join([]string{m[1], m[2], m[3], m[4]}, " "))
		}
	}
	return rows
}

func TestInvariantsIndexGenerator_Calibration(t *testing.T) {
	root := t.TempDir()

	const outsideBefore = "# Index\n\nHand-written intro, mentions UNGUARDED and | pipes |.\n\n"
	const outsideAfter = "\n## Prose after\n\nHand-written tail.\n"
	writeInvFixture(t, root, "docs/INVARIANTS.md",
		outsideBefore+invIndexBeginMark+"\nstale placeholder\n"+invIndexEndMark+"\n"+outsideAfter)

	// Legacy file: 3 column-0 bullets, the 2nd UNGUARDED only on a continuation
	// line after a blank line; an indented nested bullet and prose that says
	// UNGUARDED outside any bullet are not counted; the Format line says it too.
	writeInvFixture(t, root, "b/pkg/INVARIANTS.md", "# b/pkg\n\n"+
		"Format: `INV-B-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.\n\n"+
		"## Section\n\n"+
		"- **INV-B-01** Guarded rule.\n  Guard: `TestX`.\n"+
		"- **INV-B-02** A rule whose continuation line says\n  nothing yet.\n\n  Second paragraph: UNGUARDED (#1).\n"+
		"- **INV-B-03** Another guarded rule. Guard: `TestY`.\n  - **INV-B-99** nested, not a column-0 bullet.\n\n"+
		"## Next\nPlain prose that mentions UNGUARDED but is no bullet.\n")
	// Fragment-only package: INVARIANTS.md is prose; 2 fragments, one UNGUARDED;
	// INVARIANTS.d/README.md is not a fragment.
	writeInvFixture(t, root, "a/frag/INVARIANTS.md", "# a/frag\n\nFormat: `INV-A-NN ... UNGUARDED (#issue)`.\n")
	writeInvFixture(t, root, "a/frag/INVARIANTS.d/INV-A-one.md", "- **INV-A-one** Guarded. Guard: `TestA`.\n")
	writeInvFixture(t, root, "a/frag/INVARIANTS.d/INV-A-two.md", "- **INV-A-two** Open. UNGUARDED (#2)\n")
	writeInvFixture(t, root, "a/frag/INVARIANTS.d/README.md", "- **INV-A-readme** not a fragment. UNGUARDED\n")
	// Uppercase first letter: byte order puts it before every lowercase path.
	writeInvFixture(t, root, "Zed/INVARIANTS.md", "- **INV-Z-01** One. Guard: `TestZ`.\n")
	// Row label decoration kept from the hand-written table.
	writeInvFixture(t, root, "server/http/INVARIANTS.md", "- **INV-HTTP-01** One. Guard: `TestH`.\n")
	// The separate fuzzkit/ module is excluded, as documented.
	writeInvFixture(t, root, "fuzzkit/diffkit/INVARIANTS.md", "- **INV-FUZZDIFF-01** Excluded. UNGUARDED\n")
	writeInvFixture(t, root, "fuzzkit/diffkit/INVARIANTS.d/INV-FUZZDIFF-x.md", "- **INV-FUZZDIFF-x** Excluded.\n")

	// A hostile locale must not change the order: the script pins LC_ALL=C.
	hostile := []string{"LC_ALL=en_US.UTF-8", "LANG=en_US.UTF-8"}

	out, code := runInvIndexGen(t, root, hostile)
	if code != 0 {
		t.Fatalf("regenerate: exit %d: %s", code, out)
	}
	if !strings.Contains(out, "4 packages: 7 invariants, 5 guarded, 2 UNGUARDED") {
		t.Errorf("regenerate summary: got %q", out)
	}
	generated := readInvFixture(t, root, "docs/INVARIANTS.md")
	wantRows := []string{
		"`Zed` 1 1 0",
		"`a/frag` 2 1 1",
		"`b/pkg` 3 2 1",
		"`server/http` (+ `handlers`) 1 1 0",
	}
	if got := invFixtureRows(t, generated); strings.Join(got, "\n") != strings.Join(wantRows, "\n") {
		t.Errorf("rows:\n got  %q\n want %q", got, wantRows)
	}
	if strings.Contains(generated, "Total") {
		t.Errorf("the generator must not write a Total row:\n%s", generated)
	}
	if !strings.HasPrefix(generated, outsideBefore+invIndexBeginMark+"\n") || !strings.HasSuffix(generated, invIndexEndMark+"\n"+outsideAfter) {
		t.Errorf("text outside the markers changed:\n%s", generated)
	}
	if problems := append(checkInvariantsIndex(generated), invariantsIndexMarkerProblems(generated)...); len(problems) != 0 {
		t.Errorf("a freshly generated document must pass the index checks: %v", problems)
	}
	if problems := invariantsIndexRowFileProblems(root, generated); len(problems) != 0 {
		t.Errorf("row files of a freshly generated document: %v", problems)
	}

	// --check is silent on a fresh block and a second run changes nothing.
	if out, code := runInvIndexGen(t, root, hostile, "--check"); code != 0 {
		t.Errorf("--check on a fresh block: exit %d: %s", code, out)
	}
	if out, code := runInvIndexGen(t, root, hostile); code != 0 || !strings.Contains(out, "already up to date") {
		t.Errorf("second run: exit %d, want 'already up to date': %s", code, out)
	}
	if got := readInvFixture(t, root, "docs/INVARIANTS.md"); got != generated {
		t.Errorf("a no-op run rewrote the file")
	}

	// A hand edit inside the block is stale; --check reports it and does not
	// write; a regenerate restores the generated text byte for byte.
	handEdited := strings.Replace(generated, "| 3 | 2 | 1 |", "| 3 | 3 | 0 |", 1)
	if handEdited == generated {
		t.Fatal("fixture: the planted hand edit did not apply")
	}
	writeInvFixture(t, root, "docs/INVARIANTS.md", handEdited)
	if out, code := runInvIndexGen(t, root, hostile, "--check"); code != 1 || !strings.Contains(out, "stale") {
		t.Errorf("--check on a hand-edited block: want exit 1 and 'stale', got exit %d: %s", code, out)
	}
	if got := readInvFixture(t, root, "docs/INVARIANTS.md"); got != handEdited {
		t.Errorf("--check modified the file")
	}
	if out, code := runInvIndexGen(t, root, hostile); code != 0 {
		t.Fatalf("regenerate after hand edit: exit %d: %s", code, out)
	}
	if got := readInvFixture(t, root, "docs/INVARIANTS.md"); got != generated {
		t.Errorf("regenerate did not restore the generated block:\n%s", got)
	}

	// A new fragment makes the block stale; the regenerated row counts it, and a
	// new package gets its row without anyone editing the index.
	writeInvFixture(t, root, "a/frag/INVARIANTS.d/INV-A-three.md", "- **INV-A-three** Guarded. Guard: `TestA3`.\n")
	writeInvFixture(t, root, "c/new/INVARIANTS.md", "- **INV-C-01** First. Guard: `TestC`.\n")
	if out, code := runInvIndexGen(t, root, hostile, "--check"); code != 1 {
		t.Errorf("--check after adding a fragment and a package: want exit 1, got %d: %s", code, out)
	}
	if out, code := runInvIndexGen(t, root, hostile); code != 0 {
		t.Fatalf("regenerate after adding: exit %d: %s", code, out)
	}
	after := readInvFixture(t, root, "docs/INVARIANTS.md")
	wantAfter := []string{
		"`Zed` 1 1 0",
		"`a/frag` 3 2 1",
		"`b/pkg` 3 2 1",
		"`c/new` 1 1 0",
		"`server/http` (+ `handlers`) 1 1 0",
	}
	if got := invFixtureRows(t, after); strings.Join(got, "\n") != strings.Join(wantAfter, "\n") {
		t.Errorf("rows after adding:\n got  %q\n want %q", got, wantAfter)
	}

	// Hand-written text edited outside the markers survives a regenerate.
	edited := strings.Replace(after, "Hand-written tail.", "Edited tail.", 1)
	writeInvFixture(t, root, "docs/INVARIANTS.md", edited)
	if out, code := runInvIndexGen(t, root, hostile); code != 0 || !strings.Contains(out, "already up to date") {
		t.Errorf("an edit outside the markers must not make the block stale: exit %d: %s", code, out)
	}
	if got := readInvFixture(t, root, "docs/INVARIANTS.md"); got != edited {
		t.Errorf("a regenerate altered text outside the markers")
	}
}

// TestInvariantsIndexGenerator_RefusesBrokenMarkers: with a missing, duplicated
// or reversed marker pair the replacement would be ambiguous, so the script
// exits 2 and leaves the file alone, in both modes.
func TestInvariantsIndexGenerator_RefusesBrokenMarkers(t *testing.T) {
	cases := map[string]string{
		"no markers":        "# Index\n| Package | File |\n",
		"begin only":        "x\n" + invIndexBeginMark + "\ny\n",
		"end only":          "x\n" + invIndexEndMark + "\ny\n",
		"two pairs":         invIndexBeginMark + "\n" + invIndexEndMark + "\n" + invIndexBeginMark + "\n" + invIndexEndMark + "\n",
		"end before begin":  invIndexEndMark + "\nmid\n" + invIndexBeginMark + "\n",
		"marker with extra": invIndexBeginMark + " trailing\n" + invIndexEndMark + "\n",
	}
	for name, doc := range cases {
		root := t.TempDir()
		writeInvFixture(t, root, "docs/INVARIANTS.md", doc)
		writeInvFixture(t, root, "p/INVARIANTS.md", "- **INV-P-01** One. Guard: `T`.\n")
		for _, args := range [][]string{nil, {"--check"}} {
			out, code := runInvIndexGen(t, root, nil, args...)
			if code != 2 {
				t.Errorf("%s %v: want exit 2, got %d: %s", name, args, code, out)
			}
			if got := readInvFixture(t, root, "docs/INVARIANTS.md"); got != doc {
				t.Errorf("%s %v: the file was modified", name, args)
			}
		}
	}
}
