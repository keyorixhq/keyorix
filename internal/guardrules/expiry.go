// Package guardrules holds the two rules every repo-wide guard test follows
// (docs/guard-rollout-contract.md):
//
//   - No calendar at PR time. A guard never decides pass/fail from the wall
//     clock. An exemption row with an expiry date is either present or not;
//     whether its date has passed is checked by the nightly job on main
//     (scripts/guard-expiry-report.sh), which warns 7 days ahead and keeps one
//     GitHub issue up to date. CheckExpiry is the only sanctioned way for a
//     test to look at such a date.
//   - Report-only first. A new repo-wide guard reports through Rollout, which
//     turns its failures into log lines on PR and merge-queue runs while a
//     docs/guard-rollout.d/<TestName>.tsv row lists it. Main pushes and the
//     nightly run set KEYORIX_GUARD_ROLLOUT=enforce, so the guard is already
//     blocking there; deleting the row makes it blocking everywhere.
//
// TestGuardTestsDoNotReadTheCalendar (this package) enforces the first rule
// over every _test.go file in the repository.
package guardrules

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	// EnvExpiryToday is set only by the nightly job (YYYY-MM-DD, UTC). When it
	// is unset, CheckExpiry validates the row's format and nothing else.
	EnvExpiryToday = "KEYORIX_GUARD_EXPIRY_TODAY"
	// EnvExpiryReport names a file CheckExpiry appends one TSV line to for
	// every row that is due or expired (nightly job only).
	EnvExpiryReport = "KEYORIX_GUARD_EXPIRY_REPORT"
	// WarnDays is how far ahead the nightly job warns.
	WarnDays = 7
	// DateLayout is the only accepted expiry format.
	DateLayout = "2006-01-02"
)

// Expiry is one dated exemption: a ledger row, a registry entry or a constant.
type Expiry struct {
	Source  string // where the date lives, e.g. "docs/full-row-write-exempt.tsv:12"
	Key     string // what the row exempts
	Expires string // YYYY-MM-DD; the row is valid through the end of that day (UTC)
	Note    string // reason or issue, copied into the nightly issue
}

// CheckExpiry fails the test if e.Expires is not a YYYY-MM-DD date. It never
// reads the clock: only when EnvExpiryToday is set (the nightly job) does it
// compare the date with that day, log a warning WarnDays ahead, fail on an
// expired row and append due/expired rows to EnvExpiryReport.
//
// Call it from a test whose name ends in NotExpired: the nightly job runs
// exactly those (-run 'NotExpired$') in every package that calls CheckExpiry.
func CheckExpiry(t testing.TB, e Expiry) {
	t.Helper()
	exp, err := time.Parse(DateLayout, e.Expires)
	if err != nil {
		t.Errorf("%s: %s: expiry %q is not YYYY-MM-DD: %v", e.Source, e.Key, e.Expires, err)
		return
	}
	todayStr := os.Getenv(EnvExpiryToday)
	if todayStr == "" {
		return
	}
	today, err := time.Parse(DateLayout, todayStr)
	if err != nil {
		t.Fatalf("%s=%q is not YYYY-MM-DD: %v", EnvExpiryToday, todayStr, err)
	}
	days := DaysLeft(exp, today)
	state := ""
	switch {
	case days < 0:
		state = "expired"
		t.Errorf("%s: %s expired on %s (%s)", e.Source, e.Key, e.Expires, e.Note)
	case days <= WarnDays:
		state = "due"
		t.Logf("WARNING: %s: %s expires in %d day(s) on %s (%s)", e.Source, e.Key, days, e.Expires, e.Note)
	default:
		return
	}
	appendReport(t, fmt.Sprintf("%s\t%d\t%s\t%s\t%s\t%s\t%s", state, days, e.Expires, e.Source, e.Key, oneLine(e.Note), t.Name()))
}

// DaysLeft is the number of whole days from today until the last valid day
// exp: 0 on the day itself, -1 the day after.
func DaysLeft(exp, today time.Time) int {
	return int(exp.Sub(today).Hours() / 24)
}

func appendReport(t testing.TB, line string) {
	t.Helper()
	path := os.Getenv(EnvExpiryReport)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 G703 -- path set by the nightly job
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintln(f, line); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
