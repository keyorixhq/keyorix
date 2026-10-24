package storage

// invariants_schema_epoch_text_test.go -- RELEASE-PREP-2 item 4.
//
// INV-STORAGE-02 in INVARIANTS.md quotes the current schema epoch and compatibility
// floor ("now epoch E, floor F"). It said "now 3 ... floor stays 2" long after the code
// had moved to epoch 6 and floor 3, because the number lived only in prose. This test
// reads the number out of the prose and compares it with currentSchemaEpoch and
// minCompatibleSchemaEpoch, so the sentence cannot go stale again: a bump of either
// constant fails here until INVARIANTS.md is updated in the same change.
//
// What it does NOT check: the history after the numbers (which epoch added what).

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var inv02Numbers = regexp.MustCompile(`now epoch (\d+), floor (\d+)`)

// inv02Entry returns the text of the INV-STORAGE-02 bullet: from its marker to the next
// bullet or heading.
func inv02Entry(md string) (string, bool) {
	_, rest, ok := strings.Cut(md, "- **INV-STORAGE-02**")
	if !ok {
		return "", false
	}
	if i := strings.Index(rest, "\n- **INV-"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, "\n## "); i >= 0 {
		rest = rest[:i]
	}
	return rest, true
}

// inv02Quoted returns the epoch and floor the INV-STORAGE-02 text states.
func inv02Quoted(md string) (epoch, floor int, err string) {
	entry, ok := inv02Entry(md)
	if !ok {
		return 0, 0, "no INV-STORAGE-02 entry"
	}
	m := inv02Numbers.FindStringSubmatch(entry)
	if m == nil {
		return 0, 0, "INV-STORAGE-02 does not state `now epoch E, floor F`"
	}
	epoch, _ = strconv.Atoi(m[1])
	floor, _ = strconv.Atoi(m[2])
	return epoch, floor, ""
}

func TestInvariantsStorage02_QuotesTheCodesEpochAndFloor(t *testing.T) {
	b, err := os.ReadFile("INVARIANTS.md")
	if err != nil {
		t.Fatal(err)
	}
	epoch, floor, problem := inv02Quoted(string(b))
	if problem != "" {
		t.Fatalf("INVARIANTS.md: %s (state the numbers the code has: epoch %d, floor %d)", problem, currentSchemaEpoch, minCompatibleSchemaEpoch)
	}
	if epoch != currentSchemaEpoch || floor != minCompatibleSchemaEpoch {
		t.Fatalf("INVARIANTS.md INV-STORAGE-02 says `now epoch %d, floor %d`, the code has currentSchemaEpoch = %d and minCompatibleSchemaEpoch = %d: "+
			"update the sentence (and the history after it) in the same change that bumps them",
			epoch, floor, currentSchemaEpoch, minCompatibleSchemaEpoch)
	}
}

// TestInvariantsStorage02_TextCheckCatchesStaleNumbers is the red proof for the parser: the
// text this check was written for (the one that said 3 and 2), a missing sentence and a
// missing entry are each reported, and the current numbers are read back.
func TestInvariantsStorage02_TextCheckCatchesStaleNumbers(t *testing.T) {
	stale := "- **INV-STORAGE-02** `currentSchemaEpoch` (now 3: 2 for purge_at, floor raised to 2; 3 for the additive table, floor stays 2) has not silently bumped.\n- **INV-STORAGE-03** next\n"
	if _, _, problem := inv02Quoted(stale); problem == "" {
		t.Fatal("the old prose, which states no `now epoch E, floor F`, must be reported")
	}
	if _, _, problem := inv02Quoted("- **INV-STORAGE-03** only\n"); problem == "" {
		t.Fatal("a missing entry must be reported")
	}
	// The numbers of INV-STORAGE-03 must not be read as INV-STORAGE-02's.
	other := "- **INV-STORAGE-02** no numbers here.\n- **INV-STORAGE-03** now epoch 9, floor 9\n"
	if _, _, problem := inv02Quoted(other); problem == "" {
		t.Fatal("numbers from the next entry must not be attributed to INV-STORAGE-02")
	}
	e, f, problem := inv02Quoted("- **INV-STORAGE-02** (now epoch 7, floor 4) text\n- **INV-STORAGE-03** x\n")
	if problem != "" || e != 7 || f != 4 {
		t.Fatalf("got %d, %d, %q; want 7, 4", e, f, problem)
	}
}
