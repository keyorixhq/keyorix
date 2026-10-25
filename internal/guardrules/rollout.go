package guardrules

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const (
	// RolloutDir holds one <TestName>.tsv row per guard still in report-only mode.
	RolloutDir = "docs/guard-rollout.d"
	// EnvRollout=enforce makes every listed guard blocking. CI sets it on pushes
	// to main and on the nightly schedule, never on pull_request or merge_group.
	EnvRollout = "KEYORIX_GUARD_ROLLOUT"
	// EnvRolloutReport names a file that gets one TSV line per report-only
	// guard that would have failed (test name, failure count, first message).
	EnvRolloutReport = "KEYORIX_GUARD_ROLLOUT_REPORT"
)

// RolloutRow is one docs/guard-rollout.d/<Test>.tsv file: test, package
// directory, the PR that introduces the guard, and why it is report-only.
type RolloutRow struct {
	Test, Package, IntroducedBy, Reason string
}

// ParseRolloutRow parses the single row of a rollout fragment.
func ParseRolloutRow(name string, data []byte) (RolloutRow, error) {
	var rows []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, line)
	}
	if len(rows) != 1 {
		return RolloutRow{}, fmt.Errorf("%s: want exactly one row, got %d", name, len(rows))
	}
	f := strings.Split(rows[0], "\t")
	if len(f) != 4 {
		return RolloutRow{}, fmt.Errorf("%s: want 4 tab-separated columns (test, package, introduced_by, reason), got %d", name, len(f))
	}
	r := RolloutRow{Test: f[0], Package: f[1], IntroducedBy: f[2], Reason: f[3]}
	if want := strings.TrimSuffix(filepath.Base(name), ".tsv"); r.Test != want {
		return RolloutRow{}, fmt.Errorf("%s: test column %q must match the file name %q", name, r.Test, want)
	}
	if !strings.HasPrefix(r.Test, "Test") || r.Package == "" || !strings.HasPrefix(r.IntroducedBy, "#") || strings.TrimSpace(r.Reason) == "" {
		return RolloutRow{}, fmt.Errorf("%s: test must start with Test, package and reason must be set, introduced_by must be #NNNN", name)
	}
	return r, nil
}

// Rollout returns the testing.TB a repo-wide guard must report its findings
// through. A guard without a docs/guard-rollout.d row gets t back unchanged
// (blocking). A listed guard, unless EnvRollout=enforce, gets a wrapper whose
// Error/Errorf/Fail only log ("GUARD REPORT-ONLY") and whose Fatal/FailNow log
// and skip, so the run stays green and the finding stays visible.
func Rollout(t *testing.T) testing.TB {
	t.Helper()
	return rollout(t, filepath.Join(srcpath.RepoRoot(), RolloutDir))
}

func rollout(t *testing.T, dir string) testing.TB {
	t.Helper()
	name, _, _ := strings.Cut(t.Name(), "/")
	path := filepath.Join(dir, name+".tsv")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed directory, test name
	if errors.Is(err, fs.ErrNotExist) {
		return t
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	row, err := ParseRolloutRow(path, data)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv(EnvRollout) == "enforce" {
		t.Logf("guard rollout: %s is listed in %s/%s.tsv but %s=enforce: blocking", name, RolloutDir, name, EnvRollout)
		return t
	}
	r := &reportOnly{TB: t, row: row}
	t.Cleanup(r.summary)
	return r
}

type reportOnly struct {
	testing.TB
	row   RolloutRow
	count int
	first string
}

func (r *reportOnly) note(msg string) {
	r.TB.Helper()
	r.count++
	if r.first == "" {
		r.first = msg
	}
	r.TB.Logf("GUARD REPORT-ONLY (%s/%s.tsv, would fail): %s", RolloutDir, r.row.Test, msg)
}

func (r *reportOnly) stop() {
	r.TB.Helper()
	r.TB.Skipf("GUARD REPORT-ONLY: %s stopped at a fatal finding; it becomes blocking when %s/%s.tsv is deleted", r.row.Test, RolloutDir, r.row.Test)
}

func (r *reportOnly) Error(args ...any) { r.TB.Helper(); r.note(fmt.Sprint(args...)) }
func (r *reportOnly) Errorf(format string, args ...any) {
	r.TB.Helper()
	r.note(fmt.Sprintf(format, args...))
}
func (r *reportOnly) Fail()             { r.TB.Helper(); r.note("Fail()") }
func (r *reportOnly) FailNow()          { r.TB.Helper(); r.note("FailNow()"); r.stop() }
func (r *reportOnly) Fatal(args ...any) { r.TB.Helper(); r.note(fmt.Sprint(args...)); r.stop() }
func (r *reportOnly) Fatalf(f string, a ...any) {
	r.TB.Helper()
	r.note(fmt.Sprintf(f, a...))
	r.stop()
}

func (r *reportOnly) summary() {
	if r.count == 0 {
		r.TB.Logf("guard rollout: %s is report-only (%s) and found nothing", r.row.Test, r.row.IntroducedBy)
		return
	}
	r.TB.Logf("GUARD REPORT-ONLY: %s would have failed with %d finding(s); it is report-only until %s/%s.tsv is deleted", r.row.Test, r.count, RolloutDir, r.row.Test)
	path := os.Getenv(EnvRolloutReport)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 G703 -- path set by CI
	if err != nil {
		r.TB.Logf("guard rollout: cannot open %s: %v", path, err)
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "would-fail\t%s\t%d\t%s\n", r.row.Test, r.count, oneLine(r.first))
}
