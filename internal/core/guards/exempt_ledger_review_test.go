// exempt_ledger_review_test.go — process guard on the exemption ledgers that the
// structural race guards consult (C-GUARD-3 item 4).
//
// The root cause behind the 15 cross-replica races of 2026-10-03 (#2646-#2660,
// found by the independent review #2662) was not a missing check: GUARD-2's
// check-then-act guard existed and fired. Its author then classified every hit
// as safe in docs/check-then-act-lock-exempt.tsv, and nobody else read those
// rows. An exemption is a claim that a guard's finding does not matter; this
// test makes "someone other than the author checked that claim" a recorded,
// machine-checked fact for every row.
//
// The rule, per row of every registered ledger:
//   - added_by is non-empty (the session or PR that added the row);
//   - reviewed_by is non-empty and differs from added_by (case-insensitively).
//
// Where the reviewer is recorded:
//   - docs/check-then-act-lock-exempt.tsv and docs/atomicity-exempt.tsv: in the
//     sidecars docs/check-then-act-lock-exempt.reviewed.tsv (flat file) and
//     docs/atomicity-exempt.reviewed.d/ (one fragment per row, no flat file),
//     keyed by the ledger's first column (function). The ledger itself is left untouched because the race-fix
//     PRs edit it. Every ledger key needs a sidecar row and every sidecar row a
//     ledger key, so a row added to the ledger fails until it is reviewed.
//   - ledgers created with the columns built in (full-row-write-exempt.tsv,
//     child-parent-liveness-exempt.tsv): directly, at the column positions
//     declared in exemptLedgers.
//
// Discovery is derived: every docs/*exempt*.tsv must be registered in
// exemptLedgers (or, for a ledger that predates this rule, in
// legacyUnreviewedLedgers with its follow-up issue), so a new ledger cannot
// silently opt out.
//
// What this does NOT prove: that the reviewer actually read the code, or that
// "C-FOO-REVIEW" is a different person than "C-FOO". It records who vouched,
// and refuses the one shape that is certainly wrong (the author vouching for
// themself). That is the strongest thing a file can check.
package guards

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// exemptLedger describes one exemption ledger. Column indexes are 0-based over
// the tab-separated data rows. keyCols form the row key. A ledger with a
// sidecar names it; otherwise addedByCol/reviewedByCol point into the ledger.
type exemptLedger struct {
	keyCols       []int
	sidecar       string
	addedByCol    int
	reviewedByCol int
	reasonCol     int // -1: no reason column to scan for "pending: #NNNN"
}

var exemptLedgers = map[string]exemptLedger{
	"check-then-act-lock-exempt.tsv": {keyCols: []int{0}, sidecar: "check-then-act-lock-exempt.reviewed.tsv", reasonCol: 2},
	// Brought under the rule by #2693 (PR #4543; rows reviewed by REVIEW-4543-DEEP-1). A sidecar for the same
	// reason as check-then-act: several readers parse the ledger's three columns.
	"atomicity-exempt.tsv": {keyCols: []int{0}, sidecar: "atomicity-exempt.reviewed.tsv", reasonCol: 2},
	// Added by the C-GUARD-3 guards; listed here so whichever of those PRs lands
	// first is already under the rule. A registered ledger that does not exist
	// yet is skipped (TestExemptLedgers_RegisteredLedgersExist lists them).
	"full-row-write-exempt.tsv":        {keyCols: []int{0, 1, 2}, addedByCol: 5, reviewedByCol: 6, reasonCol: 3},
	"child-parent-liveness-exempt.tsv": {keyCols: []int{0, 1, 2}, addedByCol: 5, reviewedByCol: 6, reasonCol: 3},
	// GUARD-1's best-effort-after-commit ledger (#2561). Columns:
	// <package>:<function>#<callee>, guard, reason, added_by, reviewed_by.
	// Carries them inline rather than in a sidecar because the format is new in
	// that PR, so there is no existing ledger shape to preserve.
	"besteffort-exempt.tsv": {keyCols: []int{0}, addedByCol: 3, reviewedByCol: 4, reasonCol: 2},
}

// legacyUnreviewedLedgers predate the review rule. Each is named with the issue
// that tracks bringing it under the rule; it is NOT silently skipped — the test
// logs it on every run. Empty since #2693 brought atomicity-exempt.tsv under the rule.
var legacyUnreviewedLedgers = map[string]string{}

const exemptLedgerDir = "../../../docs"

type reviewLedgerRow struct {
	line     int
	fields   []string
	file     string // display path of the file the row came from (set by readExemptLedgerRows)
	fragment bool   // the row came from <name>.d/*.tsv, not the flat file
}

// where is "<file>:<line>" for a row read by readExemptLedgerRows.
func (r reviewLedgerRow) where() string {
	return fmt.Sprintf("%s:%d", r.file, r.line)
}

func readReviewLedgerRows(t *testing.T, path string) []reviewLedgerRow {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var rows []reviewLedgerRow
	for i, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, reviewLedgerRow{line: i + 1, fields: strings.Split(line, "\t")})
	}
	return rows
}

// readExemptLedgerRows reads an exemption ledger the dual-read way (the same
// convention as internal/core/guards readLedgerRows and
// docs/review-coverage.d/README.md): the flat docs/<name> PLUS every *.tsv in
// the sibling docs/<name minus .tsv>.d/ directory. A missing directory means
// zero fragments. Comment and blank lines are skipped in both. dups lists each
// key (the keyCols columns) that appears twice where at least one of the two
// rows is a fragment, naming both places; a key repeated only inside the flat
// file is not reported, as before.
// dir-listing-ok: ledger fragment *.tsv files under docs/<name>.d/
func readExemptLedgerRows(t *testing.T, dir, name string, keyCols []int) (rows []reviewLedgerRow, dups []string) {
	t.Helper()
	flat := "docs/" + name
	for _, r := range readReviewLedgerRows(t, filepath.Join(dir, name)) {
		r.file = flat
		rows = append(rows, r)
	}
	fragDir := strings.TrimSuffix(name, ".tsv") + ".d"
	frags, err := filepath.Glob(filepath.Join(dir, fragDir, "*.tsv"))
	require.NoError(t, err)
	sort.Strings(frags)
	for _, f := range frags {
		for _, r := range readReviewLedgerRows(t, f) {
			r.file = "docs/" + fragDir + "/" + filepath.Base(f)
			r.fragment = true
			rows = append(rows, r)
		}
	}
	seen := map[string]reviewLedgerRow{}
	for _, r := range rows {
		k := ledgerKey(r, keyCols)
		prev, ok := seen[k]
		if !ok {
			seen[k] = r
			continue
		}
		if prev.fragment || r.fragment {
			dups = append(dups, fmt.Sprintf("duplicate key %q at %s and %s", strings.ReplaceAll(k, "\t", " "), prev.where(), r.where()))
		}
	}
	return rows, dups
}

func ledgerKey(r reviewLedgerRow, cols []int) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		if c < len(r.fields) {
			parts[i] = r.fields[c]
		}
	}
	return strings.Join(parts, "\t")
}

func field(r reviewLedgerRow, c int) string {
	if c < 0 || c >= len(r.fields) {
		return ""
	}
	return strings.TrimSpace(r.fields[c])
}

// checkReviewed returns a problem description for one (added_by, reviewed_by)
// pair, or "".
func checkReviewed(addedBy, reviewedBy string) string {
	switch {
	case addedBy == "":
		return "added_by is empty"
	case reviewedBy == "":
		return "reviewed_by is empty — the row has not been independently reviewed"
	case strings.EqualFold(addedBy, reviewedBy):
		return fmt.Sprintf("reviewed_by %q equals added_by — an exemption cannot be reviewed by the session/PR that added it", reviewedBy)
	}
	return ""
}

// readSidecarRows reads a ledger's review sidecar the dual-read way: the flat
// docs/<sidecar> when it exists, PLUS every *.tsv in docs/<sidecar minus
// .tsv>.d/. A sidecar first written after GUARD-COLLISION-NOV-1 has no flat file
// at all (a new flat list is refused by single_file_allowlist_guard_test.go), so
// a missing flat file is zero rows, not an error. Each row's file is recorded for
// messages; duplicates are reported by the caller across both sources.
// dir-listing-ok: sidecar fragment *.tsv files under docs/<sidecar>.d/
func readSidecarRows(t *testing.T, dir, sidecar string) []reviewLedgerRow {
	t.Helper()
	var rows []reviewLedgerRow
	if _, err := os.Stat(filepath.Join(dir, sidecar)); err == nil {
		for _, r := range readReviewLedgerRows(t, filepath.Join(dir, sidecar)) {
			r.file = "docs/" + sidecar
			rows = append(rows, r)
		}
	} else if !os.IsNotExist(err) {
		require.NoError(t, err)
	}
	fragDir := strings.TrimSuffix(sidecar, ".tsv") + ".d"
	frags, err := filepath.Glob(filepath.Join(dir, fragDir, "*.tsv"))
	require.NoError(t, err)
	sort.Strings(frags)
	for _, f := range frags {
		for _, r := range readReviewLedgerRows(t, f) {
			r.file = "docs/" + fragDir + "/" + filepath.Base(f)
			r.fragment = true
			rows = append(rows, r)
		}
	}
	return rows
}

// sidecarWhere names where a missing sidecar row belongs: the flat
// docs/<sidecar> when it exists, otherwise its docs/<sidecar minus .tsv>.d/
// fragment directory.
func sidecarWhere(dir, sidecar string) string {
	if _, err := os.Stat(filepath.Join(dir, sidecar)); err == nil {
		return "docs/" + sidecar
	}
	return "docs/" + strings.TrimSuffix(sidecar, ".tsv") + ".d/ (one <key>.tsv fragment per row, see its README.md)"
}

// dir-listing-ok: ledger *.tsv files under docs/
func discoverExemptLedgers(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*exempt*.tsv"))
	require.NoError(t, err)
	var out []string
	for _, p := range paths {
		if !strings.HasSuffix(p, ".reviewed.tsv") {
			out = append(out, filepath.Base(p))
		}
	}
	sort.Strings(out)
	return out
}

func exemptLedgerProblems(t *testing.T, dir string) []string {
	t.Helper()
	var problems []string
	for _, name := range discoverExemptLedgers(t, dir) {
		l, ok := exemptLedgers[name]
		if !ok {
			if why, legacy := legacyUnreviewedLedgers[name]; legacy {
				t.Logf("NOT under the review rule (legacy): docs/%s — %s", name, why)
				continue
			}
			problems = append(problems, fmt.Sprintf("docs/%s is an exemption ledger not registered in exemptLedgers (internal/core/guards/exempt_ledger_review_test.go): give it added_by/reviewed_by columns or a .reviewed.tsv sidecar and register it", name))
			continue
		}
		rows, dups := readExemptLedgerRows(t, dir, name, l.keyCols)
		problems = append(problems, dups...)
		if l.sidecar == "" {
			for _, r := range rows {
				if p := checkReviewed(field(r, l.addedByCol), field(r, l.reviewedByCol)); p != "" {
					problems = append(problems, fmt.Sprintf("%s %s: %s", r.where(), strings.ReplaceAll(ledgerKey(r, l.keyCols), "\t", " "), p))
				}
			}
			continue
		}
		side := map[string]reviewLedgerRow{}
		for _, r := range readSidecarRows(t, dir, l.sidecar) {
			k := ledgerKey(r, l.keyCols)
			if _, dup := side[k]; dup {
				problems = append(problems, fmt.Sprintf("%s duplicate sidecar row for %q", r.where(), k))
			}
			side[k] = r
			// Sidecar columns: key cols..., added_by, reviewed_by.
			n := len(l.keyCols)
			if len(r.fields) != n+2 {
				problems = append(problems, fmt.Sprintf("%s want %d columns (key, added_by, reviewed_by), got %d", r.where(), n+2, len(r.fields)))
				continue
			}
			if p := checkReviewed(field(r, n), field(r, n+1)); p != "" {
				problems = append(problems, fmt.Sprintf("%s %s: %s", r.where(), k, p))
			}
		}
		keys := map[string]bool{}
		for _, r := range rows {
			k := ledgerKey(r, l.keyCols)
			keys[k] = true
			if _, ok := side[k]; !ok {
				problems = append(problems, fmt.Sprintf("%s %s has no row in %s — add one naming who added it and who (someone else) reviewed it", r.where(), k, sidecarWhere(dir, l.sidecar)))
			}
		}
		for k, r := range side {
			if !keys[k] {
				problems = append(problems, fmt.Sprintf("%s %s matches no row of docs/%s — delete it", r.where(), k, name))
			}
		}
	}
	sort.Strings(problems)
	return problems
}

// TestExemptLedgers_EveryRowIndependentlyReviewed is the guard.
func TestExemptLedgers_EveryRowIndependentlyReviewed(t *testing.T) {
	if p := exemptLedgerProblems(t, exemptLedgerDir); len(p) > 0 {
		t.Errorf("%d exemption-review problem(s):\n  %s", len(p), strings.Join(p, "\n  "))
	}
}

// TestExemptLedgers_RegisteredLedgersExist logs registered ledgers that are not
// on disk yet (a guard PR still in flight), and fails for a registered ledger
// whose sidecar exists without it.
func TestExemptLedgers_RegisteredLedgersExist(t *testing.T) {
	for name, l := range exemptLedgers {
		_, err := os.Stat(filepath.Join(exemptLedgerDir, name))
		if os.IsNotExist(err) {
			t.Logf("registered ledger docs/%s is not on disk (its guard has not landed yet)", name)
			if l.sidecar != "" {
				_, serr := os.Stat(filepath.Join(exemptLedgerDir, l.sidecar))
				require.Truef(t, os.IsNotExist(serr), "docs/%s exists without its ledger docs/%s", l.sidecar, name)
			}
		}
	}
}

// TestExemptLedgers_Calibration: the rule goes red on each bad shape and green on
// a good one, over a scratch docs directory.
func TestExemptLedgers_Calibration(t *testing.T) {
	write := func(dir, name, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	run := func(files map[string]string) []string {
		dir := t.TempDir()
		for n, b := range files {
			write(dir, n, b)
		}
		return exemptLedgerProblems(t, dir)
	}
	good := map[string]string{
		"check-then-act-lock-exempt.tsv":          "# header\nF1\tCLASS\treason\treview\n",
		"check-then-act-lock-exempt.reviewed.tsv": "# header\nF1\tC-GUARD-2\tC-GUARD2-EXEMPT-REVIEW\n",
		"full-row-write-exempt.tsv":               "a.go\tF\tUser\treason\t-\tC-GUARD-3\tC-GUARD3-REVIEW\n",
	}
	require.Empty(t, run(good))

	for name, bad := range map[string]map[string]string{
		"self-reviewed sidecar row":  {"check-then-act-lock-exempt.tsv": "F1\tC\tr\tx\n", "check-then-act-lock-exempt.reviewed.tsv": "F1\tC-GUARD-2\tc-guard-2\n"},
		"empty reviewer":             {"check-then-act-lock-exempt.tsv": "F1\tC\tr\tx\n", "check-then-act-lock-exempt.reviewed.tsv": "F1\tC-GUARD-2\t\n"},
		"ledger row with no sidecar": {"check-then-act-lock-exempt.tsv": "F1\tC\tr\tx\nF2\tC\tr\tx\n", "check-then-act-lock-exempt.reviewed.tsv": "F1\tA\tB\n"},
		"orphan sidecar row":         {"check-then-act-lock-exempt.tsv": "F1\tC\tr\tx\n", "check-then-act-lock-exempt.reviewed.tsv": "F1\tA\tB\nF9\tA\tB\n"},
		"inline self-review":         {"full-row-write-exempt.tsv": "a.go\tF\tUser\treason\t-\tC-GUARD-3\tC-GUARD-3\n"},
		"inline no added_by":         {"full-row-write-exempt.tsv": "a.go\tF\tUser\treason\t-\t\tC-GUARD3-REVIEW\n"},
		"unregistered ledger":        {"new-thing-exempt.tsv": "x\ty\n"},
	} {
		require.NotEmptyf(t, run(bad), "%s must be rejected", name)
	}
}

// TestReadExemptLedgerRows_DualRead: the ledger's keys are the flat file's plus
// every *.tsv of the sibling <name>.d/ directory, so the review rule keeps
// working after scripts/ledgers/migrate-to-fragments.sh moves rows out of the
// flat file.
func TestReadExemptLedgerRows_DualRead(t *testing.T) {
	const name = "check-then-act-lock-exempt.tsv"
	cases := []struct {
		name     string
		flat     string
		frags    map[string]string // nil: no .d directory at all
		wantKeys []string
		wantDups []string
	}{
		{name: "flat only", flat: "# h\nF1\tC\tr\nF2\tC\tr\n", wantKeys: []string{"F1", "F2"}},
		{name: "fragment only", flat: "# h\n", frags: map[string]string{"F1.tsv": "F1\tC\tr\n", "F2.tsv": "F2\tC\tr\n"}, wantKeys: []string{"F1", "F2"}},
		{name: "both", flat: "F1\tC\tr\n", frags: map[string]string{"F2.tsv": "F2\tC\tr\n"}, wantKeys: []string{"F1", "F2"}},
		{
			name: "duplicate key flat vs fragment", flat: "F1\tC\tr\n", frags: map[string]string{"F1.tsv": "F1\tC\tr\n"},
			wantKeys: []string{"F1", "F1"},
			wantDups: []string{`duplicate key "F1" at docs/` + name + `:1 and docs/check-then-act-lock-exempt.d/F1.tsv:1`},
		},
		{
			name: "duplicate key between two fragments", flat: "# h\n", frags: map[string]string{"a.tsv": "F1\tC\tr\n", "b.tsv": "F1\tC\tr\n"},
			wantKeys: []string{"F1", "F1"},
			wantDups: []string{`duplicate key "F1" at docs/check-then-act-lock-exempt.d/a.tsv:1 and docs/check-then-act-lock-exempt.d/b.tsv:1`},
		},
		{name: "comment-only fragment", flat: "F1\tC\tr\n", frags: map[string]string{"c.tsv": "# nothing here\n\n", "F2.tsv": "F2\tC\tr\n"}, wantKeys: []string{"F1", "F2"}},
		{name: "missing .d directory", flat: "F1\tC\tr\n", wantKeys: []string{"F1"}},
		{name: "non-tsv file in .d is ignored", flat: "F1\tC\tr\n", frags: map[string]string{"README.md": "F9\tC\tr\n"}, wantKeys: []string{"F1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(tc.flat), 0o600))
			if tc.frags != nil {
				fd := filepath.Join(dir, "check-then-act-lock-exempt.d")
				require.NoError(t, os.Mkdir(fd, 0o750))
				for n, b := range tc.frags {
					require.NoError(t, os.WriteFile(filepath.Join(fd, n), []byte(b), 0o600))
				}
			}
			rows, dups := readExemptLedgerRows(t, dir, name, []int{0})
			var keys []string
			for _, r := range rows {
				keys = append(keys, ledgerKey(r, []int{0}))
			}
			require.Equal(t, tc.wantKeys, keys)
			require.Equal(t, tc.wantDups, dups)
		})
	}
}

// TestExemptLedgers_FragmentRowsAreReviewed: a fragment row needs a sidecar row
// like a flat row (green when it has one, red when it has none), and a sidecar
// row for a key that only exists as a fragment is not an orphan.
func TestExemptLedgers_FragmentRowsAreReviewed(t *testing.T) {
	run := func(flat, sidecar string, frags map[string]string) []string {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "check-then-act-lock-exempt.tsv"), []byte(flat), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "check-then-act-lock-exempt.reviewed.tsv"), []byte(sidecar), 0o600))
		fd := filepath.Join(dir, "check-then-act-lock-exempt.d")
		require.NoError(t, os.Mkdir(fd, 0o750))
		for n, b := range frags {
			require.NoError(t, os.WriteFile(filepath.Join(fd, n), []byte(b), 0o600))
		}
		return exemptLedgerProblems(t, dir)
	}
	require.Empty(t, run("# h\n", "F1\tC-GUARD-2\tC-GUARD2-EXEMPT-REVIEW\n", map[string]string{"F1.tsv": "F1\tC\tr\n"}))
	p := run("# h\n", "# h\n", map[string]string{"F1.tsv": "F1\tC\tr\n"})
	require.Len(t, p, 1)
	require.Contains(t, p[0], "docs/check-then-act-lock-exempt.d/F1.tsv:1")
	require.Contains(t, p[0], "has no row in docs/check-then-act-lock-exempt.reviewed.tsv")
	require.NotEmpty(t, run("F1\tC\tr\n", "F1\tA\tB\n", map[string]string{"F1.tsv": "F1\tC\tr\n"}), "flat+fragment duplicate must be rejected")
}

// TestExemptLedgers_SidecarFragments: a sidecar kept only as <sidecar>.d/*.tsv
// fragments (no flat file, as docs/atomicity-exempt.reviewed.d is) is read like a
// flat one — green when every ledger row has a reviewed fragment, red on each bad
// shape the flat sidecar is red on.
func TestExemptLedgers_SidecarFragments(t *testing.T) {
	run := func(ledger string, frags map[string]string) []string {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "atomicity-exempt.tsv"), []byte(ledger), 0o600))
		fd := filepath.Join(dir, "atomicity-exempt.reviewed.d")
		require.NoError(t, os.Mkdir(fd, 0o750))
		for n, b := range frags {
			require.NoError(t, os.WriteFile(filepath.Join(fd, n), []byte(b), 0o600))
		}
		return exemptLedgerProblems(t, dir)
	}
	const ledger = "# h\nF1\tB\treason\nF2\tD\treason\n"
	require.Empty(t, run(ledger, map[string]string{
		"F1.tsv": "F1\tSession O\tREVIEW-4543-DEEP-1\n",
		"F2.tsv": "# comment\nF2\tPAT-GUARD-1\tREVIEW-4543-DEEP-1\n",
	}))
	p := run(ledger, map[string]string{"F1.tsv": "F1\tSession O\tREVIEW-4543-DEEP-1\n"})
	require.Len(t, p, 1)
	require.Contains(t, p[0], "has no row in docs/atomicity-exempt.reviewed.d/", "with no flat sidecar the message names the fragment directory")

	for name, frags := range map[string]map[string]string{
		"ledger row with no fragment": {"F1.tsv": "F1\tSession O\tREVIEW-4543-DEEP-1\n"},
		"self-reviewed fragment": {
			"F1.tsv": "F1\tSession O\tREVIEW-4543-DEEP-1\n", "F2.tsv": "F2\tPAT-GUARD-1\tpat-guard-1\n",
		},
		"orphan fragment": {
			"F1.tsv": "F1\tSession O\tREVIEW-4543-DEEP-1\n", "F2.tsv": "F2\tPAT-GUARD-1\tREVIEW-4543-DEEP-1\n",
			"F9.tsv": "F9\tX\tY\n",
		},
		"duplicate key across fragments": {
			"F1.tsv": "F1\tSession O\tREVIEW-4543-DEEP-1\n", "F1b.tsv": "F1\tSession O\tREVIEW-4543-DEEP-1\n",
			"F2.tsv": "F2\tPAT-GUARD-1\tREVIEW-4543-DEEP-1\n",
		},
		"wrong column count": {
			"F1.tsv": "F1\tSession O\n", "F2.tsv": "F2\tPAT-GUARD-1\tREVIEW-4543-DEEP-1\n",
		},
	} {
		require.NotEmptyf(t, run(ledger, frags), "%s must be rejected", name)
	}
}

var pendingRowRe = regexp.MustCompile(`pending: #(\d+)`)

// pendingExemption is one "pending: #NNNN" mention in a registered ledger row.
type pendingExemption struct{ where, pr string }

// pendingExemptionRows scans the reason column of every row of every registered
// ledger, reading the flat file PLUS the <name>.d/*.tsv fragments
// (readExemptLedgerRows), so a pending row that lives only in a fragment is seen.
func pendingExemptionRows(t *testing.T, dir string) []pendingExemption {
	t.Helper()
	var rows []pendingExemption
	for _, name := range discoverExemptLedgers(t, dir) {
		l, ok := exemptLedgers[name]
		if !ok || l.reasonCol < 0 {
			continue
		}
		ledgerRows, _ := readExemptLedgerRows(t, dir, name, l.keyCols)
		for _, r := range ledgerRows {
			for _, m := range pendingRowRe.FindAllStringSubmatch(field(r, l.reasonCol), -1) {
				rows = append(rows, pendingExemption{r.where(), m[1]})
			}
		}
	}
	return rows
}

// TestExemptLedgers_PendingRowsNotMerged: a row exempting a site that an open fix
// PR repairs says "pending: #NNNN". Once #NNNN merges the row is stale and must be
// removed. Needs GitHub: skipped (with the reason) when GH_TOKEN is unset or the API
// is unreachable. The ledgers' own guards fail a pending row past its expiry date
// regardless, so an offline run is bounded, not blind.
func TestExemptLedgers_PendingRowsNotMerged(t *testing.T) {
	rows := pendingExemptionRows(t, exemptLedgerDir)
	if len(rows) == 0 {
		return
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		t.Skipf("GH_TOKEN unset: cannot check whether the %d pending exemption row(s) refer to merged PRs", len(rows))
	}
	client := &http.Client{Timeout: 10 * time.Second}
	merged := map[string]bool{}
	for _, r := range rows {
		if _, done := merged[r.pr]; done {
			continue
		}
		req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/keyorixhq/keyorix/pulls/"+r.pr, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := client.Do(req)
		if err != nil {
			t.Skipf("GitHub API unreachable (%v): cannot check pending exemption rows", err)
		}
		var body struct {
			Merged bool `json:"merged"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decErr != nil {
			t.Skipf("GitHub API returned %d for PR #%s: cannot check pending exemption rows", resp.StatusCode, r.pr)
		}
		merged[r.pr] = body.Merged
	}
	var stale []string
	for _, r := range rows {
		if merged[r.pr] {
			stale = append(stale, fmt.Sprintf("%s says pending: #%s, but #%s has merged — remove the row", r.where, r.pr, r.pr))
		}
	}
	require.Emptyf(t, stale, "%d stale pending exemption row(s):\n  %s", len(stale), strings.Join(stale, "\n  "))
}
