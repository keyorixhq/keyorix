package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRunBillingReport_MatchesOldCLIOutputShape is a golden-output parity check against
// internal/cli/billing/billing.go's runReportRemote/printBillingReport.
func TestRunBillingReport_MatchesOldCLIOutputShape(t *testing.T) {
	var calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		calledPath = r.URL.Path + "?" + r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"from":"2026-01-01T00:00:00Z","to":"2026-02-01T00:00:00Z","generated_at":"2026-02-01T10:00:00Z",`+
			`"projects":[{"project_id":1,"project_name":"acme-prod","secret_count":5,"secret_reads":42,"secret_writes":3,`+
			`"secret_rotations":1,"unique_users":2,"machine_reads":10}],`+
			`"totals":{"projects":1,"secret_count":5,"secret_reads":42,"secret_writes":3,"secret_rotations":1,"unique_users":2,"machine_reads":10}}}`)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)

	billingReportFrom = "2026-01-01T00:00:00Z"
	billingReportTo = "2026-02-01T00:00:00Z"
	billingReportProjectID = ""
	billingReportFormat = "table"

	out := captureStdout(t, func() {
		if err := billingReportCmd.RunE(billingReportCmd, nil); err != nil {
			t.Fatalf("billing report: %v", err)
		}
	})
	if calledPath != "/api/v1/admin/billing/report?from=2026-01-01T00%3A00%3A00Z&to=2026-02-01T00%3A00%3A00Z" {
		t.Fatalf("called path = %q", calledPath)
	}
	if !containsAll(out, "Billing report 2026-01-01", "2026-02-01", "PROJECT", "SECRETS", "READS", "WRITES", "ROTATIONS", "UNIQUE USERS", "MACHINE READS",
		"acme-prod", "Totals (1 project(s)): 5 secrets  42 reads  3 writes  1 rotations  2 unique users  10 machine reads") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunBillingReport_InvalidFromRejected(t *testing.T) {
	billingReportFrom = "not-a-date"
	billingReportTo = "2026-02-01T00:00:00Z"
	if err := billingReportCmd.RunE(billingReportCmd, nil); err == nil {
		t.Fatal("billing report with an invalid --from returned no error")
	}
}
