package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setRiskCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunRiskList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 8's own test requirement) against
// internal/cli/risk/risk.go's listCmd.
func TestRunRiskList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/risk-exceptions" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"exceptions":[{"id":7,"title":"Legacy SoD gap","category":"sod","reference":"alice","justification":"vendor migration in progress","status":"active","expires_at":"2026-12-31T00:00:00Z","created_by":1,"approved":true}]}}`)
	}))
	defer srv.Close()
	setRiskCreds(t, srv)
	riskListAll = false

	out := captureStdout(t, func() {
		if err := riskListCmd.RunE(riskListCmd, nil); err != nil {
			t.Fatalf("risk list: %v", err)
		}
	})
	if !containsAll(out, "[active, approved] #7 Legacy SoD gap (category=sod, ref=\"alice\")", "expires 2026-12-31T00:00:00Z — vendor migration in progress") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunRiskApprove_MatchesOldCLIOutputShape(t *testing.T) {
	var calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			calledPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setRiskCreds(t, srv)
	riskApproveID = 7

	out := captureStdout(t, func() {
		if err := riskApproveCmd.RunE(riskApproveCmd, nil); err != nil {
			t.Fatalf("risk approve: %v", err)
		}
	})
	if calledPath != "/api/v1/risk-exceptions/7/approve" {
		t.Fatalf("called path = %q", calledPath)
	}
	if !containsAll(out, "Risk exception 7 approved.") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunRiskRevoke_MatchesOldCLIOutputShape(t *testing.T) {
	var calledPath, calledMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		calledPath, calledMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setRiskCreds(t, srv)
	riskRevokeID = 9

	out := captureStdout(t, func() {
		if err := riskRevokeCmd.RunE(riskRevokeCmd, nil); err != nil {
			t.Fatalf("risk revoke: %v", err)
		}
	})
	if calledPath != "/api/v1/risk-exceptions/9" || calledMethod != http.MethodDelete {
		t.Fatalf("called = %s %s", calledMethod, calledPath)
	}
	if !containsAll(out, "Risk exception 9 revoked.") {
		t.Fatalf("output = %q", out)
	}
}
