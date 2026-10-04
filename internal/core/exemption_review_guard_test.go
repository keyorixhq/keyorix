// exemption_review_guard_test.go — C-GUARD-3 guard 4: a process guard on the
// exemption ledgers themselves. The root cause #2662 found behind 15 missed
// cross-replica races was not a weak guard but a weak review: GUARD-2's author
// classified its own guard's exemptions, and 13 of 31 "safe" rows were not.
// This makes "someone other than the author reviewed every exemption" a
// checked fact rather than a convention:
//
//   - docs/check-then-act-lock-exempt.tsv: every row needs a row (same key,
//     first column) in docs/check-then-act-lock-exempt.reviewed.tsv, and every
//     sidecar row needs its original — a new exemption cannot land without a
//     recorded reviewer, a deleted one cannot leave a dangling review. (A
//     sidecar, not a new column, because the race-fix PRs edit the original.)
//   - every ledger under docs/ whose header row (first non-comment line) has
//     both an added_by and a reviewed_by column — the sidecar above, and the
//     exemption TSVs C-GUARD-3 created with those columns built in — must have,
//     on every row, a non-empty reviewed_by that shares no session/PR token
//     with added_by.
//   - a row whose text says `pending: #NNNN` (or `ahead: #NNNN`) names a
//     race-fix PR that has not merged yet; once it has, the row must be
//     deleted (or lose the marker). Checked against the
//     GitHub API when GH_TOKEN is set and the API answers; skipped (never
//     failed) otherwise. The deterministic backstop is each ledger's own
//     expires column, checked by that ledger's guard.
//
// What this does NOT establish: that the reviewer actually reviewed anything,
// or that the review was right. It checks that a reviewer distinct from the
// author is named. A ledger without both columns in its header is not
// discovered (TestExemptionReview_KnownLedgersAreDiscovered pins the ones
// that must be).
package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	cTAExemptFile         = "../../docs/check-then-act-lock-exempt.tsv"
	cTAExemptReviewedFile = "../../docs/check-then-act-lock-exempt.reviewed.tsv"
)

type ledgerRow struct {
	line int
	cols map[string]string
	raw  string
}

// readLedger returns the header columns and the data rows of a TSV whose first
// non-comment, non-blank line is a header. Rows with the wrong column count
// fail the test.
func readLedger(t *testing.T, path string) ([]string, []ledgerRow) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var header []string
	var rows []ledgerRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		cells := strings.Split(line, "\t")
		if header == nil {
			header = cells
			continue
		}
		if len(cells) != len(header) {
			t.Errorf("%s:%d: %d columns, header has %d", path, ln, len(cells), len(header))
			continue
		}
		r := ledgerRow{line: ln, cols: map[string]string{}, raw: line}
		for i, h := range header {
			r.cols[h] = cells[i]
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return header, rows
}

// firstColumnKeys reads a ledger with NO header (the original
// check-then-act file: every non-comment line is a row) and returns column 1.
func firstColumnKeys(t *testing.T, path string) map[string]int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	keys := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		keys[strings.SplitN(line, "\t", 2)[0]] = ln
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return keys
}

var reviewTokenRe = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9-]*`)

// reviewProblem returns why a row's reviewer is not independent of its
// author, or "" if it is. Tokens are case-folded [A-Za-z0-9-] runs (a #NNN PR
// reference becomes its number); a reviewer token collides with an author
// token when equal to it or extending it with "-…", so "C-GUARD-3 (#2690)"
// collides with "c-guard-3", "C-GUARD-3-EXEMPT-REVIEW" and "#2690" alike.
func reviewProblem(addedBy, reviewedBy string) string {
	addedBy, reviewedBy = strings.TrimSpace(addedBy), strings.TrimSpace(reviewedBy)
	if reviewedBy == "" {
		return "reviewed_by is empty"
	}
	if addedBy == "" {
		return "added_by is empty"
	}
	a := map[string]bool{}
	for _, tok := range reviewTokenRe.FindAllString(strings.ToLower(addedBy), -1) {
		a[tok] = true
	}
	for _, tok := range reviewTokenRe.FindAllString(strings.ToLower(reviewedBy), -1) {
		for at := range a {
			if tok == at || strings.HasPrefix(tok, at+"-") {
				return fmt.Sprintf("reviewed_by %q names the same session/PR as added_by %q (%q) — the author cannot review their own exemption", reviewedBy, addedBy, at)
			}
		}
	}
	return ""
}

// reviewedLedgers discovers every docs/ TSV whose header has both columns.
func reviewedLedgers(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../../docs/*.tsv")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var out []string
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
				continue
			}
			cols := map[string]bool{}
			for _, c := range strings.Split(line, "\t") {
				cols[c] = true
			}
			if cols["added_by"] && cols["reviewed_by"] {
				out = append(out, p)
			}
			break
		}
		_ = f.Close()
	}
	return out
}

func TestExemptionReview_CheckThenActSidecarCoversEveryRow(t *testing.T) {
	orig := firstColumnKeys(t, cTAExemptFile)
	if len(orig) == 0 {
		t.Fatalf("%s has no rows — moved or emptied? update this guard", cTAExemptFile)
	}
	header, rows := readLedger(t, cTAExemptReviewedFile)
	if strings.Join(header, "\t") != "function\tadded_by\treviewed_by" {
		t.Fatalf("%s: header must be function, added_by, reviewed_by; got %q", cTAExemptReviewedFile, header)
	}
	side := map[string]int{}
	for _, r := range rows {
		k := r.cols["function"]
		if _, dup := side[k]; dup {
			t.Errorf("%s:%d: duplicate row for %s", cTAExemptReviewedFile, r.line, k)
		}
		side[k] = r.line
	}
	for k, ln := range orig {
		if _, ok := side[k]; !ok {
			t.Errorf("%s:%d: exemption %s has no row in %s — record added_by and an independent reviewed_by before it lands", cTAExemptFile, ln, k, cTAExemptReviewedFile)
		}
	}
	for k, ln := range side {
		if _, ok := orig[k]; !ok {
			t.Errorf("%s:%d: %s has no row in %s any more — delete this sidecar row", cTAExemptReviewedFile, ln, k, cTAExemptFile)
		}
	}
}

func TestExemptionReview_EveryRowIndependentlyReviewed(t *testing.T) {
	ledgers := reviewedLedgers(t)
	for _, p := range ledgers {
		_, rows := readLedger(t, p)
		for _, r := range rows {
			if msg := reviewProblem(r.cols["added_by"], r.cols["reviewed_by"]); msg != "" {
				t.Errorf("%s:%d: %s", p, r.line, msg)
			}
		}
	}
}

// TestExemptionReview_KnownLedgersAreDiscovered pins the discovery: a ledger
// that loses either column from its header would otherwise drop out of the
// check silently. Ledgers created by C-GUARD-3 in other PRs are pinned when
// present (they may land in either order relative to this one).
func TestExemptionReview_KnownLedgersAreDiscovered(t *testing.T) {
	found := map[string]bool{}
	for _, p := range reviewedLedgers(t) {
		found[filepath.Base(p)] = true
	}
	for _, name := range []string{"check-then-act-lock-exempt.reviewed.tsv", "full-row-write-exempt.tsv", "parent-liveness-exempt.tsv"} {
		if _, err := os.Stat("../../docs/" + name); err != nil {
			if name == "check-then-act-lock-exempt.reviewed.tsv" {
				t.Errorf("docs/%s is missing", name)
			}
			continue
		}
		if !found[name] {
			t.Errorf("docs/%s exists but its header lacks added_by/reviewed_by — it is no longer checked", name)
		}
	}
}

func TestExemptionReview_ReviewProblemCalibration(t *testing.T) {
	for _, c := range []struct {
		added, reviewed string
		ok              bool
	}{
		{"GUARD-2", "C-GUARD2-EXEMPT-REVIEW", true},
		{"C-GUARD-3", "C-GUARD-3-EXEMPT-REVIEW", false}, // shares the token c-guard-3
		{"C-GUARD-3", "", false},
		{"", "C-GUARD2-EXEMPT-REVIEW", false},
		{"C-GUARD-3 (#2690)", "#2690", false},
		{"C-GUARD-3 (#2690)", "C-GUARD3-EXEMPT-REVIEW (#2701)", true},
		{"c-guard-3", "C-GUARD-3", false},
	} {
		got := reviewProblem(c.added, c.reviewed) == ""
		if got != c.ok {
			t.Errorf("reviewProblem(%q, %q): independent=%v, want %v", c.added, c.reviewed, got, c.ok)
		}
	}
}

// pendingPRRefRe matches the two markers the C-GUARD-3 ledgers use for a row
// tied to an open race-fix PR: `pending: #N` (delete the row when #N merges)
// and `ahead: #N` (drop the marker when #N merges).
var pendingPRRefRe = regexp.MustCompile(`(pending|ahead): #(\d+)`)

// pendingRowFindings scans every TSV matching docsGlob for `pending: #NNNN`
// rows and asks apiBase+NNNN whether that PR merged. It returns one finding
// per row whose PR has merged, or a non-empty skip reason when the check could
// not run (no token, API unreachable or not answering 200).
func pendingRowFindings(docsGlob, apiBase, token string) (findings []string, skip string, err error) {
	paths, err := filepath.Glob(docsGlob)
	if err != nil {
		return nil, "", err
	}
	type ref struct {
		file, kind string
		line       int
		pr         string
	}
	var refs []ref
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, "", err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			for _, m := range pendingPRRefRe.FindAllStringSubmatch(line, -1) {
				refs = append(refs, ref{file: p, kind: m[1], line: i + 1, pr: m[2]})
			}
		}
	}
	if len(refs) == 0 {
		return nil, "no pending rows", nil
	}
	if token == "" {
		return nil, fmt.Sprintf("%d pending rows not checked against GitHub: GH_TOKEN/GITHUB_TOKEN unset (the expires column is the offline backstop)", len(refs)), nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	merged := map[string]bool{}
	for _, r := range refs {
		if _, done := merged[r.pr]; done {
			continue
		}
		req, err := http.NewRequest(http.MethodGet, apiBase+r.pr, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Sprintf("GitHub API unreachable (%v); pending rows not checked", err), nil
		}
		var body struct {
			Merged bool `json:"merged"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decErr != nil {
			return nil, fmt.Sprintf("GitHub API answered %d for PR #%s; pending rows not checked", resp.StatusCode, r.pr), nil
		}
		merged[r.pr] = body.Merged
	}
	for _, r := range refs {
		if !merged[r.pr] {
			continue
		}
		if r.kind == "pending" {
			findings = append(findings, fmt.Sprintf("%s:%d: row is `pending: #%s` but #%s has merged — delete the row (its site is fixed on main now)", r.file, r.line, r.pr, r.pr))
		} else {
			findings = append(findings, fmt.Sprintf("%s:%d: row is `ahead: #%s` but #%s has merged — drop the marker and its expires date (the row is permanent now)", r.file, r.line, r.pr, r.pr))
		}
	}
	return findings, "", nil
}

// TestExemptionReview_PendingRowsNotYetMerged fails when a `pending: #NNNN`
// row survives the merge of the PR it waits on. Needs GH_TOKEN (or
// GITHUB_TOKEN) and a reachable API; skips otherwise, saying which. The guards
// themselves never skip on this — only this cross-check does.
func TestExemptionReview_PendingRowsNotYetMerged(t *testing.T) {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	findings, skip, err := pendingRowFindings("../../docs/*.tsv", "https://api.github.com/repos/keyorixhq/keyorix/pulls/", token)
	if err != nil {
		t.Fatal(err)
	}
	if skip != "" {
		t.Skip(skip)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// TestExemptionReview_PendingCheckCalibration drives pendingRowFindings
// against a fake GitHub: a row pending on a merged PR is reported, one pending
// on an open PR is not, and a non-200 answer skips rather than passes.
func TestExemptionReview_PendingCheckCalibration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/pulls/") {
		case "1111":
			_, _ = w.Write([]byte(`{"merged": true}`))
		case "2222":
			_, _ = w.Write([]byte(`{"merged": false}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "x.tsv"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("site\treason\nA\tpending: #1111 fix lands\nB\tpending: #2222 fix lands\nD\tahead: #1111 helper lands\n")
	findings, skip, err := pendingRowFindings(filepath.Join(dir, "*.tsv"), srv.URL+"/pulls/", "tok")
	if err != nil || skip != "" || len(findings) != 2 || !strings.Contains(findings[0], "delete the row") || !strings.Contains(findings[1], "drop the marker") {
		t.Fatalf("merged/open: findings=%q skip=%q err=%v", findings, skip, err)
	}
	write("site\treason\nC\tpending: #3333\n")
	if findings, skip, _ = pendingRowFindings(filepath.Join(dir, "*.tsv"), srv.URL+"/pulls/", "tok"); skip == "" || len(findings) != 0 {
		t.Fatalf("404 must skip, not pass: findings=%q skip=%q", findings, skip)
	}
	if _, skip, _ = pendingRowFindings(filepath.Join(dir, "*.tsv"), srv.URL+"/pulls/", ""); !strings.Contains(skip, "unset") {
		t.Fatalf("no token must skip: %q", skip)
	}
}
