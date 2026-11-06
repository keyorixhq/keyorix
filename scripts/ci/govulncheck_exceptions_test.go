package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// TestGovulncheckCheckScript runs check-govulncheck-test.sh, the offline
// calibration of check-govulncheck.sh (both directions: a reachable,
// non-allowlisted finding fails; a clean run, a non-reachable-only finding,
// and a reachable-but-allowlisted finding all pass; govulncheck itself
// failing fails the check rather than reading as "clean"). The workflow
// jobs (ci.yml's static-analysis, govulncheck-scheduled.yml) run the real
// script against the real govulncheck output on every run; this is what
// fails the Go suite if the script's logic regresses.
func TestGovulncheckCheckScript(t *testing.T) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	out, err := exec.Command("bash", "check-govulncheck-test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("check-govulncheck-test.sh: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// govulncheckExceptionRow is one parsed row of a docs/govulncheck-exceptions.d/
// fragment. See that directory's README.md for what each field means.
type govulncheckExceptionRow struct {
	file            string
	line            int
	id              string
	module          string
	expires         string
	mitigationTests []string
	note            string
}

var govulncheckIDRe = regexp.MustCompile(`^GO-\d{4}-\d+$`)

// loadGovulncheckExceptions parses every docs/govulncheck-exceptions.d/*.tsv
// fragment and fails the test outright on a malformed row -- the same
// fail-fast-on-malformed-fragment behavior
// internal/statemap's fragment guard gives every other <pkg>/INVARIANTS.d/
// directory, applied here by hand since this isn't that registry.
func loadGovulncheckExceptions(t *testing.T) []govulncheckExceptionRow {
	t.Helper()
	dir := "../../docs/govulncheck-exceptions.d"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var rows []govulncheckExceptionRow
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".tsv") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) // #nosec G304 -- fixed, repo-relative test path
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) != 1 || lines[0] == "" {
			t.Errorf("%s: must contain exactly one row, found %d", path, len(lines))
			continue
		}
		fields := strings.Split(lines[0], "\t")
		if len(fields) != 5 {
			t.Errorf("%s:1: want 5 tab-separated fields (id, module, expires, mitigation_tests, note), got %d", path, len(fields))
			continue
		}
		id, module, expires, mitigations, note := fields[0], fields[1], fields[2], fields[3], fields[4]
		if !govulncheckIDRe.MatchString(id) {
			t.Errorf("%s:1: id %q does not look like a vuln.go.dev ID (want GO-YYYY-NNNN)", path, id)
		}
		if strings.TrimSuffix(name, ".tsv") != id {
			t.Errorf("%s: filename must be <id>.tsv — got %q for id %q", path, name, id)
		}
		var tests []string
		if mitigations != "-" {
			for tn := range strings.SplitSeq(mitigations, ",") {
				tn = strings.TrimSpace(tn)
				if tn == "" {
					t.Errorf("%s:1: mitigation_tests has an empty entry", path)
					continue
				}
				tests = append(tests, tn)
			}
		}
		rows = append(rows, govulncheckExceptionRow{
			file: path, line: 1, id: id, module: module, expires: expires,
			mitigationTests: tests, note: note,
		})
	}
	return rows
}

// TestGovulncheckExceptionsNotExpired is the nightly-evaluated half of the
// dated exception (docs/guard-rollout-contract.md rule 1, same as every
// other dated exemption in this repo): at PR time this only checks the date
// is YYYY-MM-DD. scripts/guard-expiry-report.sh discovers it by grepping for
// guardrules.CheckExpiry( the same way it discovers every other
// Test*NotExpired, sets KEYORIX_GUARD_EXPIRY_TODAY, warns 7 days ahead and
// fails on an expired row.
func TestGovulncheckExceptionsNotExpired(t *testing.T) {
	for _, r := range loadGovulncheckExceptions(t) {
		guardrules.CheckExpiry(t, guardrules.Expiry{
			Source:  r.file,
			Key:     r.id,
			Expires: r.expires,
			Note:    r.note,
		})
	}
}

// testFuncRe matches a top-level Go test function declaration.
var testFuncRe = func(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(name) + `\(t \*testing\.T\)`)
}

// TestGovulncheckExceptionsMitigationTestsExist fails if a row names a
// mitigation test that doesn't exist in the repo. A mitigation that's only
// asserted in a .tsv row's note, with no real passing test behind it, is the
// weakest tier CLAUDE.md's engineering practices describe ("assert it in
// prose") — this derives and checks the claim instead: grep the repo for
// each named `func <name>(t *testing.T)` and fail if it's missing. It does
// not run the tests (that already happens via the normal package test runs);
// it only proves the name in the row still refers to something real.
//
// This walks every _test.go file in the repository, so it is a repo-wide
// guard under docs/guard-rollout-contract.md and goes through
// guardrules.Rollout: report-only while docs/guard-rollout.d/
// TestGovulncheckExceptionsMitigationTestsExist.tsv exists, in case an
// unrelated open PR happens to rename one of the few named mitigation tests
// out from under it (the exact failure class that contract exists for —
// see TestNoRawErrorTextOnServerErrors in its own history table).
func TestGovulncheckExceptionsMitigationTestsExist(t *testing.T) {
	g := guardrules.Rollout(t)
	repoRoot := "../.."
	for _, r := range loadGovulncheckExceptions(t) {
		for _, name := range r.mitigationTests {
			found := false
			_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
				if err != nil || found {
					return nil
				}
				if d.IsDir() {
					if d.Name() == ".git" || d.Name() == "node_modules" {
						return filepath.SkipDir
					}
					return nil
				}
				if !strings.HasSuffix(path, "_test.go") {
					return nil
				}
				data, err := os.ReadFile(path) // #nosec G304 -- walking the repo's own test files
				if err != nil {
					return nil
				}
				if testFuncRe(name).Match(data) {
					found = true
				}
				return nil
			})
			if !found {
				g.Errorf("%s: mitigation_tests names %q, but no `func %s(t *testing.T)` exists anywhere in the repo", r.file, name, name)
			}
		}
	}
}
