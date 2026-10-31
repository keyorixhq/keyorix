package docsdrift

// invariants_index_malformed_test.go — calibration for the one thing
// checkInvariantsIndex used to skip without a word: a table row its patterns
// do not match (a missing cell, a link without a path, a non-numeric count).
// Such a row was left out of the sums, so the Total could be "right" for the
// rows that matched and the index still wrong.

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// TestInvariantsIndexCheck_MalformedRowIsReported plants each kind of
// malformed row into a copy of the real table (in memory; the file on disk is
// not touched) and requires exactly one problem more than the unmodified
// table has, naming the planted line. Comparing against the unmodified
// table's own problems keeps this test about the check: whether the live
// document is clean is TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp's
// job, under its rollout row, and must not turn fatal here.
func TestInvariantsIndexCheck_MalformedRowIsReported(t *testing.T) {
	g := guardrules.Rollout(t)
	doc := readDoc(g, "docs/INVARIANTS.md")
	base := checkInvariantsIndex(doc)

	const marker = "| **Total** |"
	plants := []struct{ name, row string }{
		{"non-numeric count", "| `planted/pkg` | [p/INVARIANTS.md](../p/INVARIANTS.md) | 3 | two | 1 |"},
		{"missing cell", "| `planted/pkg` | [p/INVARIANTS.md](../p/INVARIANTS.md) | 3 | 3 |"},
		{"file cell is not a link", "| `planted/pkg` | p/INVARIANTS.md | 3 | 3 | 0 |"},
		{"bold count outside the Total row", "| `planted/pkg` | [p/INVARIANTS.md](../p/INVARIANTS.md) | **3** | **3** | **0** |"},
	}
	for _, p := range plants {
		at := strings.Index(doc, marker)
		if at < 0 {
			t.Fatalf("no %q row in docs/INVARIANTS.md", marker)
		}
		planted := doc[:at] + p.row + "\n" + doc[at:]
		// Line numbers in the unmodified table's problems shift by one
		// after the planted line, so compare counts, not messages.
		got := checkInvariantsIndex(planted)
		named := 0
		for _, problem := range got {
			if strings.Contains(problem, "not counted") && strings.Contains(problem, "planted/pkg") {
				named++
			}
		}
		if len(got) != len(base)+1 || named != 1 {
			t.Errorf("%s: want the unmodified table's %d problem(s) plus one naming the planted row, got %v", p.name, len(base), got)
		}
	}

	// A "|" line after the table (prose, another table) is not part of it.
	after := strings.Replace(doc, "\n## Highest-priority UNGUARDED gaps", "\n\nNot a row.\n\n| a | b |\n|---|---|\n\n## Highest-priority UNGUARDED gaps", 1)
	if after == doc {
		t.Fatal("anchor heading not found in docs/INVARIANTS.md")
	}
	if got := checkInvariantsIndex(after); len(got) != len(base) {
		t.Errorf("a table after the counts table must not be scanned: want the unmodified table's %d problem(s), got %v", len(base), got)
	}
}
