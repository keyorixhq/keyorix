package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFetchDeploymentHygiene_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 8's own test requirement) against
// internal/cli/hygiene/hygiene.go's printRollup.
func TestFetchDeploymentHygiene_MatchesOldCLIOutputShape(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/hygiene" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"totals":{"orphaned_secrets":2,"unused_secrets":5,"expiring_secrets":1,"stale_machine_identities":3,"rotation_overdue":4},"projects":[{"project_id":9,"project_name":"payments","orphaned_secrets":2,"unused_secrets":5,"expiring_secrets":1,"stale_machine_identities":3,"rotation_overdue":4}]}}`)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
	hygieneUnusedDays, hygieneExpiringDays, hygieneStaleDays = 30, 15, 45

	out := captureStdout(t, func() {
		if err := hygieneCmd.RunE(hygieneCmd, nil); err != nil {
			t.Fatalf("hygiene: %v", err)
		}
	})
	if gotQuery == "" || !containsAll(gotQuery, "unused_days=30", "expiring_days=15", "stale_days=45") {
		t.Fatalf("query = %q", gotQuery)
	}
	if !containsAll(out, "Deployment-wide hygiene totals:", "orphaned secrets         2", "Projects with debt (1):", "payments") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestFetchDeploymentHygiene_NoDebt_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"totals":{},"projects":[]}}`)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
	hygieneUnusedDays, hygieneExpiringDays, hygieneStaleDays = 0, 0, 0

	out := captureStdout(t, func() {
		if err := hygieneCmd.RunE(hygieneCmd, nil); err != nil {
			t.Fatalf("hygiene: %v", err)
		}
	})
	if !containsAll(out, "No projects carry outstanding signals.") {
		t.Fatalf("output = %q", out)
	}
}
