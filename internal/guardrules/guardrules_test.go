package guardrules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recTB records what CheckExpiry reports instead of failing the real test.
type recTB struct {
	testing.TB
	errs, logs []string
	fatal      bool
}

func (r *recTB) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *recTB) Logf(f string, a ...any)   { r.logs = append(r.logs, fmt.Sprintf(f, a...)) }
func (r *recTB) Fatalf(f string, a ...any) {
	r.fatal = true
	r.errs = append(r.errs, fmt.Sprintf(f, a...))
}

func TestCheckExpiry_PRTimeIsCalendarFree(t *testing.T) {
	t.Setenv(EnvExpiryToday, "")
	r := &recTB{TB: t}
	CheckExpiry(r, Expiry{Source: "x.tsv:1", Key: "k", Expires: "2000-01-01"})
	if len(r.errs)+len(r.logs) != 0 {
		t.Fatalf("a long-expired row must pass when %s is unset (PR time), got errs=%v logs=%v", EnvExpiryToday, r.errs, r.logs)
	}
	r = &recTB{TB: t}
	CheckExpiry(r, Expiry{Source: "x.tsv:2", Key: "k", Expires: "18 Oct"})
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "not YYYY-MM-DD") {
		t.Fatalf("a malformed date must fail at PR time, got %v", r.errs)
	}
}

func TestCheckExpiry_NightlyWarnsSevenDaysAheadAndFailsAfter(t *testing.T) {
	report := filepath.Join(t.TempDir(), "expiry.tsv")
	t.Setenv(EnvExpiryToday, "2026-10-18")
	t.Setenv(EnvExpiryReport, report)
	cases := []struct {
		expires    string
		wantErr    bool
		wantWarn   bool
		wantReport string
	}{
		{"2026-10-26", false, false, ""},       // 8 days left: quiet
		{"2026-10-25", false, true, "due\t7"},  // 7 days: first warning
		{"2026-10-18", false, true, "due\t0"},  // last valid day
		{"2026-10-17", true, false, "expired"}, // the day after: the 18 Oct incident shape
	}
	for _, c := range cases {
		r := &recTB{TB: t}
		CheckExpiry(r, Expiry{Source: "docs/x.tsv:3", Key: "Fn Model", Expires: c.expires, Note: "pending: #1"})
		if got := len(r.errs) > 0; got != c.wantErr {
			t.Errorf("%s: error=%v, want %v (%v)", c.expires, got, c.wantErr, r.errs)
		}
		if got := len(r.logs) > 0 && strings.HasPrefix(r.logs[0], "WARNING"); got != c.wantWarn {
			t.Errorf("%s: warning=%v, want %v (%v)", c.expires, got, c.wantWarn, r.logs)
		}
	}
	data, err := os.ReadFile(report) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "due\t7\t2026-10-25\tdocs/x.tsv:3\tFn Model\tpending: #1\t") || !strings.HasPrefix(lines[2], "expired\t-1\t") {
		t.Fatalf("report lines = %q", lines)
	}
}

func TestCheckExpiry_BadTodayIsFatal(t *testing.T) {
	t.Setenv(EnvExpiryToday, "today")
	r := &recTB{TB: t}
	CheckExpiry(r, Expiry{Source: "s", Key: "k", Expires: "2026-01-01"})
	if !r.fatal {
		t.Fatal("an unparsable nightly date must stop the test, not silently pass every row")
	}
}

func writeRow(t *testing.T, dir, test string) {
	t.Helper()
	row := test + "\tinternal/guardrules\t#1\tcalibration\n"
	if err := os.WriteFile(filepath.Join(dir, test+".tsv"), []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRollout_ReportOnlyLogsInsteadOfFailing: a listed guard's Errorf and
// Fatalf keep the run green (a Fatalf skips), and the report file names it.
func TestRollout_ReportOnlyLogsInsteadOfFailing(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "rollout.tsv")
	writeRow(t, dir, t.Name())
	t.Setenv(EnvRollout, "")
	t.Setenv(EnvRolloutReport, report)
	var reached bool
	ok := t.Run("errorf", func(st *testing.T) {
		g := rollout(st, dir)
		if g == testing.TB(st) {
			st.Fatal("a listed guard must not get the raw *testing.T outside enforce mode")
		}
		g.Errorf("finding %d", 1)
		g.Fatalf("fatal finding")
		reached = true
	})
	if !ok {
		t.Fatal("report-only subtest failed; Errorf/Fatalf must only log")
	}
	if reached {
		t.Fatal("Fatalf in report-only mode must still stop the guard (it skips)")
	}
	data, err := os.ReadFile(report) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if want := "would-fail\t" + t.Name() + "\t2\tfinding 1\n"; string(data) != want {
		t.Fatalf("report = %q, want %q", data, want)
	}
}

func TestRollout_EnforceAndUnlistedAreBlocking(t *testing.T) {
	dir := t.TempDir()
	if g := rollout(t, dir); g != testing.TB(t) {
		t.Fatal("an unlisted guard must get its own *testing.T (blocking)")
	}
	writeRow(t, dir, t.Name())
	t.Setenv(EnvRollout, "enforce")
	if g := rollout(t, dir); g != testing.TB(t) {
		t.Fatalf("%s=enforce must make a listed guard blocking", EnvRollout)
	}
}

func TestParseRolloutRow_Rejects(t *testing.T) {
	for name, body := range map[string]string{
		"TestA.tsv": "TestB\tpkg\t#1\treason\n",             // name mismatch
		"TestC.tsv": "TestC\tpkg\t1\treason\n",              // introduced_by not #NNNN
		"TestD.tsv": "TestD\tpkg\t#1\n",                     // 3 columns
		"TestE.tsv": "TestE\tpkg\t#1\tr\nTestE\tp\t#2\tr\n", // two rows
	} {
		if _, err := ParseRolloutRow(name, []byte(body)); err == nil {
			t.Errorf("%s: accepted %q", name, body)
		}
	}
	if _, err := ParseRolloutRow("d/TestF.tsv", []byte("# header\nTestF\tinternal/x\t#3729\tnew guard\n")); err != nil {
		t.Errorf("valid row rejected: %v", err)
	}
}

// TestCalendarViolations_Calibration: the historical time-bomb shapes are
// flagged, the converted shape and plain timeout loops are not.
func TestCalendarViolations_Calibration(t *testing.T) {
	bad := map[string]string{
		"pending rows (full-row write, child-parent liveness)": `package x
import ("testing"; "time")
func TestPendingRowsNotExpired(t *testing.T) {
	now := time.Now().UTC()
	exp, _ := time.Parse("2006-01-02", "2026-10-18")
	if !now.Before(exp.Add(24 * time.Hour)) { t.Fatal("expired") }
}`,
		"named-lock pending date (string compare)": `package x
import ("testing"; "time")
const pendingExpires = "2026-10-18"
func TestNamedLock(t *testing.T) {
	if time.Now().UTC().Format("2006-01-02") > pendingExpires { t.Error("x") }
}`,
		"ADR open decision (clock passed to a helper)": `package x
import ("testing"; "time")
func TestADR(t *testing.T) { _ = evaluate(time.Now()) }
func evaluate(now time.Time) error { o, _ := time.Parse("2006-01-02", "2026-09-09"); _ = now.Sub(o); return nil }`,
		"time.DateOnly and an aliased import": `package x
import ("testing"; tm "time")
func TestX(t *testing.T) { d, _ := tm.Parse(tm.DateOnly, "2026-01-01"); _ = tm.Since(d) }`,
	}
	for name, src := range bad {
		if v := calendarViolations("x_test.go", []byte(src)); len(v) == 0 {
			t.Errorf("%s: not flagged", name)
		}
	}
	good := map[string]string{
		"converted: format check plus CheckExpiry": `package x
import ("testing"; "time"; "github.com/keyorixhq/keyorix/internal/guardrules")
func TestPendingRowsNotExpired(t *testing.T) {
	_, err := time.Parse("2006-01-02", "2026-10-18")
	if err != nil { t.Fatal(err) }
	guardrules.CheckExpiry(t, guardrules.Expiry{Expires: "2026-10-18"})
}`,
		"timeout loop, no dates": `package x
import ("testing"; "time")
func TestWait(t *testing.T) { deadline := time.Now().Add(time.Second); for time.Now().Before(deadline) {} }`,
		"date layout only in a comment": `package x
import ("testing"; "time")
// rows carry "2006-01-02" dates
func TestWait(t *testing.T) { _ = time.Now() }`,
	}
	for name, src := range good {
		if v := calendarViolations("x_test.go", []byte(src)); len(v) != 0 {
			t.Errorf("%s: flagged: %v", name, v)
		}
	}
}
