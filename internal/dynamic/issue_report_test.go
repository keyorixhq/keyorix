package dynamic

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// DYNAMIC-HOSTILE-TAILS-1 item 1: a database engine names its account through
// ports.ReportIssuedRole before the first statement that can create it, so core can
// revoke it even when the client library panics on that statement's reply.

// The reporter is called with the account the engine then creates, and strictly before
// the CREATE USER statement reaches the target.
func TestMySQLIssue_ReportsAccountBeforeFirstWrite(t *testing.T) {
	rec := &execRecorder{}
	useRecorder(t, rec)

	var reported []string
	var writesAtReport int
	ctx := ports.WithIssuedRoleReporter(context.Background(), func(name string) {
		reported = append(reported, name)
		writesAtReport = len(rec.statements())
	})
	eng, err := New("mysql", true, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, role, err := eng.Issue(ctx, mysqlPanicDSN, "GRANT SELECT ON app.* TO {{name}}", time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(reported) != 1 || reported[0] != role {
		t.Fatalf("reported %q, issued %q", reported, role)
	}
	if writesAtReport != 0 {
		t.Fatalf("reported after %d target statement(s), want before the first", writesAtReport)
	}
}

// Even when the very first write panics, the name was already reported and matches the
// account in the statement that may have created it.
func TestMySQLIssue_ReportedAccountMatchesCreateUserOnPanic(t *testing.T) {
	rec := &execRecorder{panicOn: "CREATE USER"}
	useRecorder(t, rec)
	captureLog(t)

	var reported string
	ctx := ports.WithIssuedRoleReporter(context.Background(), func(name string) { reported = name })
	eng, err := New("mysql", true, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = eng.Issue(ctx, mysqlPanicDSN, "", time.Minute)
	assertTypedPanicError(t, err)
	if reported == "" || !strings.Contains(strings.Join(rec.statements(), "\n"), "CREATE USER '"+reported+"'@'%'") {
		t.Fatalf("reported %q does not match the attempted CREATE USER: %q", reported, rec.statements())
	}
}

// ReportIssuedRole without a reporter in the context is a no-op (cloud engines, callers
// outside core).
func TestReportIssuedRole_NoReporterIsNoop(t *testing.T) {
	ports.ReportIssuedRole(context.Background(), "kx_dyn_x")
}
