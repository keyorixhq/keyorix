package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRunUsageShow_MatchesOldCLIOutputShape is a golden-output parity check against
// internal/cli/usage/usage.go's runShowRemote/printReport.
func TestRunUsageShow_MatchesOldCLIOutputShape(t *testing.T) {
	var calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		calledPath = r.URL.Path + "?" + r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"window_days":7,"generated_at":"2026-01-15T10:00:00Z","projects":[{"project_id":1,"project_name":"acme-prod","secret_count":5,"reads_in_window":42,"unique_readers":3}]}}`)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)

	usageShowDays = 7
	usageShowProjectID = 0
	usageShowFormat = "table"

	out := captureStdout(t, func() {
		if err := usageShowCmd.RunE(usageShowCmd, nil); err != nil {
			t.Fatalf("usage show: %v", err)
		}
	})
	if calledPath != "/api/v1/admin/usage?days=7" {
		t.Fatalf("called path = %q, want /api/v1/admin/usage?days=7", calledPath)
	}
	if !containsAll(out, "Usage report — last 7 days", "PROJECT", "SECRETS", "READS", "UNIQUE READERS", "acme-prod", "5", "42", "3") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunUsageShow_ProjectIDFilter(t *testing.T) {
	var calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		calledPath = r.URL.Path + "?" + r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"window_days":30,"generated_at":"2026-01-15T10:00:00Z","projects":[]}}`)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)

	usageShowDays = 30
	usageShowProjectID = 7
	usageShowFormat = "table"

	out := captureStdout(t, func() {
		if err := usageShowCmd.RunE(usageShowCmd, nil); err != nil {
			t.Fatalf("usage show: %v", err)
		}
	})
	if calledPath != "/api/v1/admin/usage?days=30&project_id=7" {
		t.Fatalf("called path = %q, want project_id=7 in the query", calledPath)
	}
	if !containsAll(out, "(no data)") {
		t.Fatalf("output = %q, want (no data) for an empty report", out)
	}
}
