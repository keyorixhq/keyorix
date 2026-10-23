package ci_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests feed the gate REAL data (testdata/codeql/README.md; *.sarif is gitignored, hence .sarif.json): the SARIF of
// main's go-server analysis and main's open and dismissed CodeQL alerts, served
// through the alerts-API path. With the full baseline main itself must pass;
// with one alert removed the gate must fail and say where and why, in the log
// text itself (the 23 Oct queue failures printed only the rule id there).

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "codeql", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// withoutLines drops every baseline line that contains substr.
func withoutLines(tsv, substr string) string {
	var keep []string
	for l := range strings.SplitSeq(tsv, "\n") {
		if l != "" && !strings.Contains(l, substr) {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n") + "\n"
}

func TestCodeQLGateRealSARIF(t *testing.T) {
	sarifs := map[string]string{"go-server.sarif": readFixture(t, "main-go-server.sarif.json")}
	open := readFixture(t, "main-alerts-open.tsv")
	dismissed := readFixture(t, "main-alerts-dismissed.tsv")

	cases := []struct {
		name      string
		open      string
		dismissed string
		wantFail  bool
		want      []string
		dontWant  []string
	}{
		{
			name: "main passes against its own alerts", open: open, dismissed: dismissed,
			want: []string{
				"3 result(s) with security-severity >= 7.0",
				"known on main (open or dismissed): go/disabled-certificate-check (security-severity 7.5) at scripts/metrics/surfacewalk/startup.go:50 [/language:go-server/]",
				"known on main (open or dismissed): go/clear-text-logging (security-severity 7.5) at server/admin/recover_admin.go:141",
				"known on main (open or dismissed): go/weak-sensitive-data-hashing (security-severity 7.5) at internal/storage/store/local_audit_chain.go:237",
				"every high-severity result is already an open or dismissed alert on main",
			},
			dontWant: []string{"::error", "NEW high-severity"},
		},
		{
			// Open alert 1281 removed: a result with no code flow and no related location.
			name: "open alert missing: location and message printed", open: withoutLines(open, "go/disabled-certificate-check"), dismissed: dismissed,
			wantFail: true,
			want: []string{
				"NEW high-severity result 1 of 1 [/language:go-server/]",
				"  rule:     go/disabled-certificate-check (security-severity 7.5)\n",
				"  location: scripts/metrics/surfacewalk/startup.go:50\n",
				"  message:  InsecureSkipVerify should not be used in production code.\n",
				"  flow:     -\n",
				"::error file=scripts/metrics/surfacewalk/startup.go,line=50,title=CodeQL go/disabled-certificate-check (new on this change)::CodeQL high-severity result go/disabled-certificate-check (security-severity 7.5) at scripts/metrics/surfacewalk/startup.go:50 is not an open or dismissed alert on main.",
			},
		},
		{
			// Dismissed alerts 1241/1147 removed: go/clear-text-logging, the rule of
			// the 23 Oct queue failures; the export carries a related location only.
			name: "dismissed clear-text-logging missing: related location printed", open: open, dismissed: withoutLines(dismissed, "server/admin/recover_admin.go"),
			wantFail: true,
			want: []string{
				"  rule:     go/clear-text-logging (security-severity 7.5)\n",
				"  location: server/admin/recover_admin.go:141\n",
				// CodeQL's "[text](1)" placeholder link is printed as plain text.
				"  message:  Sensitive data returned by an access to oneTimePassword flows to a logging call.\n",
				"  flow:     related server/admin/recover_admin.go:141: Sensitive data returned by an access to oneTimePassword\n",
			},
			dontWant: []string{"](1)"},
		},
		{
			// Dismissed alerts 799/17 removed: a path-problem result with a code flow.
			name: "dismissed weak hashing missing: first code-flow step printed", open: open, dismissed: withoutLines(dismissed, "local_audit_chain.go"),
			wantFail: true,
			want: []string{
				"  location: internal/storage/store/local_audit_chain.go:237\n",
				"  message:  Sensitive data (password) is used in a hashing algorithm (SHA256) that is insecure for password hashing, since it is not a computationally expensive hash function.\n",
				"  flow:     source internal/core/account.go:456: EventPasswordChangePATRevokeFailed (step 1 of 3)\n",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum := filepath.Join(t.TempDir(), "summary.md")
			out, err := runGateAPI(t, sarifs, map[string]string{"open": tc.open, "dismissed": tc.dismissed}, "", "GITHUB_STEP_SUMMARY="+sum)
			if (err != nil) != tc.wantFail {
				t.Fatalf("failed=%v, want %v\n%s", err != nil, tc.wantFail, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range tc.dontWant {
				if strings.Contains(out, w) {
					t.Errorf("output has %q:\n%s", w, out)
				}
			}
			raw, err := os.ReadFile(sum)
			if err != nil {
				t.Fatalf("no step summary written: %v", err)
			}
			s := string(raw)
			if tc.wantFail {
				if !strings.Contains(s, "### CodeQL gate: FAILED -- 1 new high-severity result(s)") {
					t.Errorf("summary lacks the failure heading:\n%s", s)
				}
				if !strings.Contains(s, "2 high-severity result(s) already known on main") {
					t.Errorf("summary lacks the known results:\n%s", s)
				}
			} else if !strings.Contains(s, "### CodeQL gate: passed") || !strings.Contains(s, "3 high-severity result(s) already known on main") {
				t.Errorf("summary of a pass is wrong:\n%s", s)
			}
		})
	}
}

// Main's JS/TS analysis next to the Go one: both pass with main's alerts; with
// dismissed alert 604 gone, the first step of its real code flow is printed.
func TestCodeQLGateRealJavaScriptSARIF(t *testing.T) {
	sarifs := map[string]string{
		"go-server.sarif":  readFixture(t, "main-go-server.sarif.json"),
		"javascript.sarif": readFixture(t, "main-javascript.sarif.json"),
	}
	open := readFixture(t, "main-alerts-open.tsv")
	dismissed := readFixture(t, "main-alerts-dismissed.tsv")
	out, err := runGateAPI(t, sarifs, map[string]string{"open": open, "dismissed": dismissed}, "")
	if err != nil || !strings.Contains(out, "2 SARIF file(s), 5 result(s) with security-severity >= 7.0") {
		t.Fatalf("main must pass: err=%v\n%s", err, out)
	}
	out, err = runGateAPI(t, sarifs, map[string]string{"open": open, "dismissed": withoutLines(dismissed, "demo/app.js")}, "")
	if err == nil {
		t.Fatalf("gate passed, want a failure:\n%s", out)
	}
	for _, w := range []string{
		"NEW high-severity result 1 of 1 [/language:javascript-typescript/]",
		"  location: demo/app.js:13\n",
		"  message:  This logs sensitive data returned by process environment as clear text.\n",
		"  flow:     source demo/app.js:6: process.env (step 1 of 2)\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// The 23 Oct queue failure (#3543), reproduced with CodeQL 2.27.3 on the
// merge-group commit: the gate must fail on exactly the two results the queue
// annotated, and say where the sensitive data comes from.
func TestCodeQLGateQueue3543Reproduction(t *testing.T) {
	sarifs := map[string]string{"go-server.sarif": readFixture(t, "queue-3543-clear-text-logging.sarif.json")}
	out, err := runGateAPI(t, sarifs, map[string]string{
		"open":      readFixture(t, "main-alerts-open.tsv"),
		"dismissed": readFixture(t, "main-alerts-dismissed.tsv"),
	}, "")
	if err == nil {
		t.Fatalf("gate passed, want the queue's failure:\n%s", out)
	}
	for _, w := range []string{
		"known on main (open or dismissed): go/clear-text-logging (security-severity 7.5) at server/admin/recover_admin.go:141",
		"NEW high-severity result 1 of 2",
		"  location: internal/core/session_undelivered.go:60\n",
		"NEW high-severity result 2 of 2",
		"  location: server/http/handlers/auth.go:879\n",
		"  message:  Sensitive data returned by an access to passwordPolicyError flows to a logging call.\n",
		"  flow:     source internal/core/account.go:425: struct literal (step 1 of 3)\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	if n := strings.Count(out, "::error "); n != 2 {
		t.Errorf("%d annotations, want 2 (as in runs 40024087095 and 40025800055):\n%s", n, out)
	}
}

// The summary table row of a new result names rule, severity, file:line,
// message and flow start.
func TestCodeQLGateSummaryRow(t *testing.T) {
	sarifs := map[string]string{"go-server.sarif": readFixture(t, "main-go-server.sarif.json")}
	sum := filepath.Join(t.TempDir(), "summary.md")
	_, err := runGateAPI(t, sarifs, map[string]string{
		"open":      readFixture(t, "main-alerts-open.tsv"),
		"dismissed": withoutLines(readFixture(t, "main-alerts-dismissed.tsv"), "local_audit_chain.go"),
	}, "", "GITHUB_STEP_SUMMARY="+sum)
	if err == nil {
		t.Fatal("gate passed, want a failure")
	}
	raw, err := os.ReadFile(sum)
	if err != nil {
		t.Fatal(err)
	}
	row := "| `go/weak-sensitive-data-hashing` | 7.5 | `internal/storage/store/local_audit_chain.go:237` | Sensitive data (password) is used in a hashing algorithm (SHA256) that is insecure for password hashing, since it is not a computationally expensive hash function. | source internal/core/account.go:456: EventPasswordChangePATRevokeFailed (step 1 of 3) |"
	if !strings.Contains(string(raw), row) {
		t.Errorf("summary lacks row\n%s\ngot:\n%s", row, raw)
	}
}

// Annotation text and properties are escaped as workflow commands require, a
// missing message keeps the following fields in place, and a Markdown pipe in a
// message does not break the summary table.
func TestCodeQLGateEscaping(t *testing.T) {
	high := rule("go/sql-injection", "8.8")
	res := `{"ruleId":"go/sql-injection","message":{"text":"100% bad | a:b, c\nsecond line"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a,b.go"},"region":{"startLine":3}}}]}`
	bare := `{"ruleId":"go/sql-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"c.go"},"region":{"startLine":9}}}]}`
	sum := filepath.Join(t.TempDir(), "summary.md")
	out, err := runGateAPI(t, map[string]string{"go.sarif": sarif(high, res+","+bare)}, nil, "", "GITHUB_STEP_SUMMARY="+sum)
	if err == nil {
		t.Fatalf("gate passed, want a failure:\n%s", out)
	}
	for _, w := range []string{
		"::error file=a%2Cb.go,line=3,title=CodeQL go/sql-injection (new on this change)::",
		"100%25 bad | a:b, c -- flow: -",
		"  location: c.go:9\n  message:  -\n  flow:     -\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "second line") {
		t.Errorf("only the first message line is printed:\n%s", out)
	}
	raw, err := os.ReadFile(sum)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `100% bad \| a:b, c`) {
		t.Errorf("summary does not escape the pipe:\n%s", raw)
	}
}

// Fail-closed paths also say why in the job summary.
func TestCodeQLGateFailClosedSummary(t *testing.T) {
	sum := filepath.Join(t.TempDir(), "summary.md")
	out, err := runGateAPI(t, map[string]string{"go.sarif": "not json"}, nil, "", "GITHUB_STEP_SUMMARY="+sum)
	if err == nil || !strings.Contains(out, "failing closed") {
		t.Fatalf("unreadable SARIF must fail closed: err=%v\n%s", err, out)
	}
	raw, err := os.ReadFile(sum)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "FAILED (fail-closed)") {
		t.Errorf("summary lacks the fail-closed reason:\n%s", raw)
	}
}
