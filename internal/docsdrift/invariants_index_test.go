package docsdrift

// invariants_index_test.go — docs/INVARIANTS.md's counts table is written by
// hand (no generator exists; internal/statemap's invariants guard says in so
// many words that it does not check it). Concurrent PRs each edit it and the
// merge resolution keeps both versions of a changed row, which left every
// package listed twice with different counts and a Total that matched neither
// (UPGRADE-RESTORE-COMPAT-1, DOCS-OPS-TAILS-2).
//
// What this checks: each package appears in one row only, each row's
// Invariants = Guarded + UNGUARDED, and there is NO hand-kept Total row: the
// column sums are computed here and logged (#4237: a hand-kept Total edited by
// two concurrent PRs merged in the queue into two Total rows or a sum that
// matched neither branch, and ejected PRs that were green on their own). Every line of the counts table (the
// "| Package |" header through the last consecutive "|" line) must be the
// header, the separator, a package row or the Total row: any other line is
// reported, because a row the patterns do not match would otherwise be left
// out of the sums without a word.
//
// What it does NOT check: that a row's numbers match the bullets in that
// package's INVARIANTS.md and INVARIANTS.d/ (they drift as invariants are
// added; re-derive by the recipe in the file's "Maintaining this index"
// section), that the linked file exists, or any "|" table elsewhere in the
// document (only the table under the "| Package |" header is scanned).

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

var (
	// | `pkg` | [file](link) | 40 | 35 | 5 |
	invIndexRowRE = regexp.MustCompile("^\\|\\s*(`[^|]+?(?:\\s+\\(\\+[^|]*\\))?)\\s*\\|\\s*\\[[^\\]]+\\]\\([^)]+\\)\\s*\\|\\s*(\\d+)\\s*\\|\\s*(\\d+)\\s*\\|\\s*(\\d+)\\s*\\|\\s*$")
	// | **Total** | | **248** | **211** | **37** |
	invIndexTotalRE = regexp.MustCompile(`^\|\s*\*\*Total\*\*\s*\|[^|]*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*$`)
	// | Package | File | Invariants | Guarded | UNGUARDED |
	invIndexHeaderRE = regexp.MustCompile(`^\|\s*Package\s*\|`)
	// |---|---|---|---|---|
	invIndexSepRE = regexp.MustCompile(`^\|[\s:|-]+\|\s*$`)
)

// checkInvariantsIndex returns one message per problem in the index document.
func checkInvariantsIndex(doc string) []string {
	problems, _, _, _ := invariantsIndexSums(doc)
	return problems
}

// invariantsIndexSums is checkInvariantsIndex plus the column sums of the
// package rows (invariants, guarded, UNGUARDED).
func invariantsIndexSums(doc string) (problems []string, inv, guarded, unguarded int) {
	type counts struct {
		inv, guarded, unguarded, line int
		text                          string // the row as written, so a message can quote it
	}
	seen := map[string]counts{}
	var order []string
	var sum counts
	var totals []counts

	inTable := false
	for i, line := range strings.Split(doc, "\n") {
		n := i + 1
		switch {
		case invIndexHeaderRE.MatchString(line):
			inTable = true
			continue
		case inTable && !strings.HasPrefix(line, "|"):
			inTable = false
		case inTable && invIndexSepRE.MatchString(line):
			continue
		}
		if m := invIndexTotalRE.FindStringSubmatch(line); m != nil {
			c := counts{line: n, text: line}
			c.inv, _ = strconv.Atoi(m[1])
			c.guarded, _ = strconv.Atoi(m[2])
			c.unguarded, _ = strconv.Atoi(m[3])
			totals = append(totals, c)
			continue
		}
		m := invIndexRowRE.FindStringSubmatch(line)
		if m == nil {
			if inTable {
				problems = append(problems, fmt.Sprintf("line %d: table row matches neither the package-row nor the Total pattern, so it is not counted: %q", n, line))
			}
			continue
		}
		pkg := strings.TrimSpace(m[1])
		c := counts{line: n, text: line}
		c.inv, _ = strconv.Atoi(m[2])
		c.guarded, _ = strconv.Atoi(m[3])
		c.unguarded, _ = strconv.Atoi(m[4])
		if first, dup := seen[pkg]; dup {
			problems = append(problems, fmt.Sprintf("line %d: package %s is listed twice: keep one row with the current counts (a concurrent PR edited the same row; recompute from main)\n  line %d: %s\n  line %d: %s", n, pkg, first.line, first.text, n, line))
		} else {
			seen[pkg] = c
			order = append(order, pkg)
		}
		if c.inv != c.guarded+c.unguarded {
			problems = append(problems, fmt.Sprintf("line %d: %s has %d invariants but %d guarded + %d UNGUARDED", n, pkg, c.inv, c.guarded, c.unguarded))
		}
		sum.inv += c.inv
		sum.guarded += c.guarded
		sum.unguarded += c.unguarded
	}

	if len(order) == 0 {
		return append(problems, "no package rows found: the row pattern no longer matches the table"), sum.inv, sum.guarded, sum.unguarded
	}
	// The table carries NO hand-kept total (#4237). Two PRs that each touched
	// the Total row, or each appended a package row above it, merged in the
	// queue into two Total rows or a sum that matched neither PR, so a PR that
	// was green on its own branch failed on the merge result. The sums are
	// derived here from the rows instead and logged by the test.
	for _, t := range totals {
		problems = append(problems, fmt.Sprintf("line %d: remove the hand-kept Total row (%s): the sums are computed by this test from the package rows, currently %d / %d / %d (invariants / guarded / UNGUARDED); a hand-kept row is what made concurrent PRs fail each other in the merge queue (#4237)",
			t.line, t.text, sum.inv, sum.guarded, sum.unguarded))
	}
	return problems, sum.inv, sum.guarded, sum.unguarded
}

func TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp(t *testing.T) {
	g := guardrules.Rollout(t)
	problems, inv, guarded, unguarded := invariantsIndexSums(readDoc(g, "docs/INVARIANTS.md"))
	for _, p := range problems {
		g.Errorf("docs/INVARIANTS.md: %s", p)
	}
	// The diagnostic a failing queue run needs: the exact sums of the tree this
	// ran on, so a mismatch is visible without re-deriving it.
	t.Logf("docs/INVARIANTS.md package rows sum to %d / %d / %d (invariants / guarded / UNGUARDED)", inv, guarded, unguarded)
}

// TestInvariantsIndexCheck_Calibration proves checkInvariantsIndex fires on
// each defect it names and stays silent on a clean table.
func TestInvariantsIndexCheck_Calibration(t *testing.T) {
	const head = "| Package | File | Invariants | Guarded | UNGUARDED |\n|---|---|---|---|---|\n"
	rowA := "| `a/core` | [a/INVARIANTS.md](../a/INVARIANTS.md) | 10 | 8 | 2 |\n"
	rowB := "| `b/http` (+ `handlers`) | [b/INVARIANTS.md](../b/INVARIANTS.md) | 5 | 5 | 0 |\n"
	rowA2 := "| `a/core` | [a/INVARIANTS.md](../a/INVARIANTS.md) | 11 | 8 | 3 |\n"
	total := "| **Total** | | **15** | **13** | **2** |\n"

	cases := []struct {
		name string
		doc  string
		want string // substring of the single expected problem; "" = clean
	}{
		{"clean", head + rowA + rowB, ""},
		{"duplicate package row", head + rowA + rowB + rowA2, "listed twice"},
		{"row does not add up", head + rowA + "| `b/http` | [b](../b) | 5 | 4 | 0 |\n", "5 invariants but 4 guarded"},
		{"hand-kept total, even a correct one", head + rowA + rowB + total, "remove the hand-kept Total row"},
		{"two totals", head + rowA + rowB + total + total, "remove the hand-kept Total row"},
		{"no rows", "# empty\n", "no package rows found"},
	}
	for _, tc := range cases {
		got := checkInvariantsIndex(tc.doc)
		switch {
		case tc.want == "" && len(got) != 0:
			t.Errorf("%s: want clean, got %v", tc.name, got)
		case tc.want == "":
		case tc.name == "two totals" && (len(got) != 2 || !strings.Contains(got[0], tc.want) || !strings.Contains(got[1], tc.want)):
			t.Errorf("%s: want one problem per Total row containing %q, got %v", tc.name, tc.want, got)
		case tc.name != "two totals" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
			t.Errorf("%s: want one problem containing %q, got %v", tc.name, tc.want, got)
		}
	}

	// The sums are derived from the rows, whatever order PRs landed them in.
	_, inv, guarded, unguarded := invariantsIndexSums(head + rowA + rowB)
	if inv != 15 || guarded != 13 || unguarded != 2 {
		t.Errorf("sums = %d / %d / %d, want 15 / 13 / 2", inv, guarded, unguarded)
	}
	_, inv2, guarded2, unguarded2 := invariantsIndexSums(head + rowB + rowA)
	if inv != inv2 || guarded != guarded2 || unguarded != unguarded2 {
		t.Errorf("sums depend on row order: %d / %d / %d vs %d / %d / %d", inv, guarded, unguarded, inv2, guarded2, unguarded2)
	}
}
