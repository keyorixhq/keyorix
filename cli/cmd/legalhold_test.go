package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setLegalHoldCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunLegalHoldStatus_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 8's own test requirement) against
// internal/cli/legalhold/legalhold.go's statusCmd.
func TestRunLegalHoldStatus_Active_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/legal-hold" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"active":true,"hold":{"id":2,"reason":"litigation X","placed_by":1,"placed_at":"2026-01-01T00:00:00Z"}}}`)
	}))
	defer srv.Close()
	setLegalHoldCreds(t, srv)

	out := captureStdout(t, func() {
		if err := legalHoldStatusCmd.RunE(legalHoldStatusCmd, nil); err != nil {
			t.Fatalf("legal-hold status: %v", err)
		}
	})
	if !containsAll(out, "LEGAL HOLD ACTIVE (id=2) since 2026-01-01T00:00:00Z", "Reason: litigation X") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunLegalHoldStatus_None_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"active":false,"hold":{}}}`)
	}))
	defer srv.Close()
	setLegalHoldCreds(t, srv)

	out := captureStdout(t, func() {
		if err := legalHoldStatusCmd.RunE(legalHoldStatusCmd, nil); err != nil {
			t.Fatalf("legal-hold status: %v", err)
		}
	})
	if !containsAll(out, "No legal hold is active. Purge jobs run normally.") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunLegalHoldPlace_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"hold":{"id":9,"reason":"audit","placed_by":1,"placed_at":"2026-01-01T00:00:00Z"}}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setLegalHoldCreds(t, srv)
	legalHoldPlaceReason = "audit"

	out := captureStdout(t, func() {
		if err := legalHoldPlaceCmd.RunE(legalHoldPlaceCmd, nil); err != nil {
			t.Fatalf("legal-hold place: %v", err)
		}
	})
	if !containsAll(out, "Legal hold placed (id=9). All purge jobs are now blocked until lifted.") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunLegalHoldLift_MatchesOldCLIOutputShape(t *testing.T) {
	var calledMethod, calledPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledMethod, calledPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{}}`)
	}))
	defer srv.Close()
	setLegalHoldCreds(t, srv)
	legalHoldLiftYes = true
	legalHoldLiftReason = "resolved"
	defer func() { legalHoldLiftYes = false }()

	cmd := legalHoldLiftCmd
	cmd.SetIn(strings.NewReader(""))

	out := captureStdout(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("legal-hold lift: %v", err)
		}
	})
	if calledMethod != http.MethodDelete || calledPath != "/api/v1/legal-hold" {
		t.Fatalf("called = %s %s", calledMethod, calledPath)
	}
	if !containsAll(out, "Legal hold lifted. Purge jobs will resume on their next tick.") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunLegalHoldLift_AbortsWithoutConfirmation(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setLegalHoldCreds(t, srv)
	legalHoldLiftYes = false
	legalHoldLiftReason = "resolved"

	cmd := legalHoldLiftCmd
	cmd.SetIn(strings.NewReader("no\n"))

	out := captureStdout(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("legal-hold lift: %v", err)
		}
	})
	if called {
		t.Fatalf("expected no request to be sent when confirmation is declined")
	}
	if !containsAll(out, "Aborted.") {
		t.Fatalf("output = %q", out)
	}
}
