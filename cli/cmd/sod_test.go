package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setSoDCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunSoDPolicyList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 8's own test requirement) against
// internal/cli/sod/sod.go's policyListCmd.
func TestRunSoDPolicyList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sod/policies" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"policies":[{"id":3,"name":"role-assign-vs-delete","description":"","permission_a":"roles.assign","permission_b":"secrets.delete"}],"count":1}}`)
	}))
	defer srv.Close()
	setSoDCreds(t, srv)

	out := captureStdout(t, func() {
		if err := sodPolicyListCmd.RunE(sodPolicyListCmd, nil); err != nil {
			t.Fatalf("sod policy list: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "role-assign-vs-delete", "roles.assign", "secrets.delete") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunSoDPolicyCreate_MatchesOldCLIOutputShape(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			body = string(b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"policy":{"id":5,"name":"n","description":"d","permission_a":"a","permission_b":"b"}}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setSoDCreds(t, srv)
	sodName, sodDesc, sodPermA, sodPermB = "n", "d", "a", "b"

	out := captureStdout(t, func() {
		if err := sodPolicyCreateCmd.RunE(sodPolicyCreateCmd, nil); err != nil {
			t.Fatalf("sod policy create: %v", err)
		}
	})
	if body == "" {
		t.Fatalf("expected a request body to be sent")
	}
	if !containsAll(out, `Created SoD policy 5 ("n"): a + b must not be held together.`) {
		t.Fatalf("output = %q", out)
	}
}

func TestRunSoDPolicyDelete_MatchesOldCLIOutputShape(t *testing.T) {
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
	setSoDCreds(t, srv)
	sodID = 3

	out := captureStdout(t, func() {
		if err := sodPolicyDeleteCmd.RunE(sodPolicyDeleteCmd, nil); err != nil {
			t.Fatalf("sod policy delete: %v", err)
		}
	})
	if calledPath != "/api/v1/sod/policies/3" || calledMethod != http.MethodDelete {
		t.Fatalf("called = %s %s", calledMethod, calledPath)
	}
	if !containsAll(out, "Deleted SoD policy 3.") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunSoDViolations_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sod/violations" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"violations":[{"policy_name":"role-assign-vs-delete","username":"alice","email":"a@x.io","permission_a":"roles.assign","permission_b":"secrets.delete"}],"count":1,"degraded":false,"degraded_reasons":null}}`)
	}))
	defer srv.Close()
	setSoDCreds(t, srv)

	out := captureStdout(t, func() {
		if err := sodViolationsCmd.RunE(sodViolationsCmd, nil); err != nil {
			t.Fatalf("sod violations: %v", err)
		}
	})
	if !containsAll(out, "1 violation(s):", "alice <a@x.io>", "roles.assign", "secrets.delete") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("short", 26); got != "short" {
		t.Fatalf("got %q", got)
	}
	if got := truncateRunes("this-is-a-very-long-policy-name", 10); got != "this-is-a…" {
		t.Fatalf("got %q", got)
	}
}
