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
// not touched) and requires exactly one problem that names the planted line.
// It first requires the unmodified table to be clean, so a red here means the
// check, not the document.
func TestInvariantsIndexCheck_MalformedRowIsReported(t *testing.T) {
	g := guardrules.Rollout(t)
	doc := readDoc(g, "docs/INVARIANTS.md")
	if got := checkInvariantsIndex(doc); len(got) != 0 {
		t.Fatalf("docs/INVARIANTS.md is not clean, fix it before reading this test: %v", got)
	}

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
		got := checkInvariantsIndex(planted)
		if len(got) != 1 || !strings.Contains(got[0], "not counted") || !strings.Contains(got[0], "planted/pkg") {
			t.Errorf("%s: want one problem naming the planted row, got %v", p.name, got)
		}
	}

	// A "|" line after the table (prose, another table) is not part of it.
	after := strings.Replace(doc, "\n## Highest-priority UNGUARDED gaps", "\n\nNot a row.\n\n| a | b |\n|---|---|\n\n## Highest-priority UNGUARDED gaps", 1)
	if after == doc {
		t.Fatal("anchor heading not found in docs/INVARIANTS.md")
	}
	if got := checkInvariantsIndex(after); len(got) != 0 {
		t.Errorf("a table after the counts table must not be scanned, got %v", got)
	}
}
