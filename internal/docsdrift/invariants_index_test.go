package docsdrift

// invariants_index_test.go — docs/INVARIANTS.md's counts table is written by
// hand (no generator exists; internal/statemap's invariants guard says in so
// many words that it does not check it). Concurrent PRs each edit it and the
// merge resolution keeps both versions of a changed row, which left every
// package listed twice with different counts and a Total that matched neither
// (UPGRADE-RESTORE-COMPAT-1, DOCS-OPS-TAILS-2).
//
// What this checks: each package appears in one row only, each row's
// Invariants = Guarded + UNGUARDED, there is exactly one Total row, and its
// three numbers are the column sums. Every line of the counts table (the
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
	var problems []string
	type counts struct{ inv, guarded, unguarded, line int }
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
			c := counts{line: n}
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
		c := counts{line: n}
		c.inv, _ = strconv.Atoi(m[2])
		c.guarded, _ = strconv.Atoi(m[3])
		c.unguarded, _ = strconv.Atoi(m[4])
		if first, dup := seen[pkg]; dup {
			problems = append(problems, fmt.Sprintf("line %d: package %s is listed twice (first at line %d): keep one row with the current counts", n, pkg, first.line))
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
		return append(problems, "no package rows found: the row pattern no longer matches the table")
	}
	switch len(totals) {
	case 0:
		problems = append(problems, "the table has no **Total** row")
	case 1:
		t := totals[0]
		if t.inv != sum.inv || t.guarded != sum.guarded || t.unguarded != sum.unguarded {
			problems = append(problems, fmt.Sprintf("line %d: Total is %d / %d / %d but the rows sum to %d / %d / %d (invariants / guarded / UNGUARDED)",
				t.line, t.inv, t.guarded, t.unguarded, sum.inv, sum.guarded, sum.unguarded))
		}
	default:
		problems = append(problems, fmt.Sprintf("the table has %d **Total** rows (lines %d and %d): keep one", len(totals), totals[0].line, totals[1].line))
	}
	return problems
}

func TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp(t *testing.T) {
	g := guardrules.Rollout(t)
	for _, p := range checkInvariantsIndex(readDoc(g, "docs/INVARIANTS.md")) {
		g.Errorf("docs/INVARIANTS.md: %s", p)
	}
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
		{"clean", head + rowA + rowB + total, ""},
		{"duplicate package row", head + rowA + rowB + rowA2 + "| **Total** | | **26** | **21** | **5** |\n", "listed twice"},
		{"total is not the sum", head + rowA + rowB + "| **Total** | | **16** | **13** | **3** |\n", "rows sum to 15 / 13 / 2"},
		{"row does not add up", head + rowA + "| `b/http` | [b](../b) | 5 | 4 | 0 |\n" + "| **Total** | | **15** | **12** | **2** |\n", "5 invariants but 4 guarded"},
		{"two totals", head + rowA + rowB + total + total, "2 **Total** rows"},
		{"no total", head + rowA + rowB, "no **Total** row"},
		{"no rows", "# empty\n", "no package rows found"},
	}
	for _, tc := range cases {
		got := checkInvariantsIndex(tc.doc)
		switch {
		case tc.want == "" && len(got) != 0:
			t.Errorf("%s: want clean, got %v", tc.name, got)
		case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
			t.Errorf("%s: want one problem containing %q, got %v", tc.name, tc.want, got)
		}
	}
}
