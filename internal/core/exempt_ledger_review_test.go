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
//   - docs/check-then-act-lock-exempt.tsv: in the sidecar
//     docs/check-then-act-lock-exempt.reviewed.tsv, keyed by the ledger's first
//     column (function). The ledger itself is left untouched because the race-fix
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
package core

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
	// Added by the C-GUARD-3 guards; listed here so whichever of those PRs lands
	// first is already under the rule. A registered ledger that does not exist
	// yet is skipped (TestExemptLedgers_RegisteredLedgersExist lists them).
	"full-row-write-exempt.tsv":         {keyCols: []int{0, 1, 2}, addedByCol: 5, reviewedByCol: 6, reasonCol: 3},
	"child-parent-liveness-exempt.tsv":  {keyCols: []int{0, 1, 2}, addedByCol: 5, reviewedByCol: 6, reasonCol: 3},
}

// legacyUnreviewedLedgers predate the review rule. Each is named with the issue
// that tracks bringing it under the rule; it is NOT silently skipped — the test
// logs it on every run.
var legacyUnreviewedLedgers = map[string]string{
	"atomicity-exempt.tsv": "#2693: needs an independent review recorded in a docs/atomicity-exempt.reviewed.tsv sidecar",
}

const exemptLedgerDir = "../../docs"

type ledgerRow struct {
	line   int
	fields []string
}

func readLedgerRows(t *testing.T, path string) []ledgerRow {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var rows []ledgerRow
	for i, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, ledgerRow{line: i + 1, fields: strings.Split(line, "\t")})
	}
	return rows
}

func ledgerKey(r ledgerRow, cols []int) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		if c < len(r.fields) {
			parts[i] = r.fields[c]
		}
	}
	return strings.Join(parts, "\t")
}

func field(r ledgerRow, c int) string {
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
			problems = append(problems, fmt.Sprintf("docs/%s is an exemption ledger not registered in exemptLedgers (internal/core/exempt_ledger_review_test.go): give it added_by/reviewed_by columns or a .reviewed.tsv sidecar and register it", name))
			continue
		}
		rows := readLedgerRows(t, filepath.Join(dir, name))
		if l.sidecar == "" {
			for _, r := range rows {
				if p := checkReviewed(field(r, l.addedByCol), field(r, l.reviewedByCol)); p != "" {
					problems = append(problems, fmt.Sprintf("docs/%s:%d %s: %s", name, r.line, strings.ReplaceAll(ledgerKey(r, l.keyCols), "\t", " "), p))
				}
			}
			continue
		}
		side := map[string]ledgerRow{}
		for _, r := range readLedgerRows(t, filepath.Join(dir, l.sidecar)) {
			k := ledgerKey(r, l.keyCols)
			if _, dup := side[k]; dup {
				problems = append(problems, fmt.Sprintf("docs/%s:%d duplicate sidecar row for %q", l.sidecar, r.line, k))
			}
			side[k] = r
			// Sidecar columns: key cols..., added_by, reviewed_by.
			n := len(l.keyCols)
			if len(r.fields) != n+2 {
				problems = append(problems, fmt.Sprintf("docs/%s:%d want %d columns (key, added_by, reviewed_by), got %d", l.sidecar, r.line, n+2, len(r.fields)))
				continue
			}
			if p := checkReviewed(field(r, n), field(r, n+1)); p != "" {
				problems = append(problems, fmt.Sprintf("docs/%s:%d %s: %s", l.sidecar, r.line, k, p))
			}
		}
		keys := map[string]bool{}
		for _, r := range rows {
			k := ledgerKey(r, l.keyCols)
			keys[k] = true
			if _, ok := side[k]; !ok {
				problems = append(problems, fmt.Sprintf("docs/%s:%d %s has no row in docs/%s — add one naming who added it and who (someone else) reviewed it", name, r.line, k, l.sidecar))
			}
		}
		for k, r := range side {
			if !keys[k] {
				problems = append(problems, fmt.Sprintf("docs/%s:%d %s matches no row of docs/%s — delete it", l.sidecar, r.line, k, name))
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

var pendingRowRe = regexp.MustCompile(`pending: #(\d+)`)

// TestExemptLedgers_PendingRowsNotMerged: a row exempting a site that an open fix
// PR repairs says "pending: #NNNN". Once #NNNN merges the row is stale and must be
// removed. Needs GitHub: skipped (with the reason) when GH_TOKEN is unset or the API
// is unreachable. The ledgers' own guards fail a pending row past its expiry date
// regardless, so an offline run is bounded, not blind.
func TestExemptLedgers_PendingRowsNotMerged(t *testing.T) {
	type pending struct{ where, pr string }
	var rows []pending
	for _, name := range discoverExemptLedgers(t, exemptLedgerDir) {
		l, ok := exemptLedgers[name]
		if !ok || l.reasonCol < 0 {
			continue
		}
		for _, r := range readLedgerRows(t, filepath.Join(exemptLedgerDir, name)) {
			for _, m := range pendingRowRe.FindAllStringSubmatch(field(r, l.reasonCol), -1) {
				rows = append(rows, pending{fmt.Sprintf("docs/%s:%d", name, r.line), m[1]})
			}
		}
	}
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
