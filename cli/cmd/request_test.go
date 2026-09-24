package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setRequestCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunRequestAccess_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 7's own test requirement) against
// internal/cli/request/access.go's runAccessRemote.
func TestRunRequestAccess_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"ID":3,"Name":"payments"}]}}`)
		case r.URL.Path == "/api/v1/projects/3/access-requests" && r.Method == http.MethodPost:
			_, _ = fmt.Fprint(w, `{"data":{"access_request":{"ID":9,"ProjectID":3,"UserID":1,"SuggestedRole":"secrets-reader","State":"pending"}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setRequestCreds(t, srv)
	requestAccessProject = "payments"
	requestAccessRole = "secrets-reader"
	requestAccessReason = ""
	defer func() { requestAccessProject, requestAccessRole = "", "" }()

	out := captureStdout(t, func() {
		if err := runRequestAccess(requestAccessCmd, nil); err != nil {
			t.Fatalf("runRequestAccess: %v", err)
		}
	})
	if !containsAll(out, `Requesting access to project "payments" (id=3)`, "self-service",
		"Access requested: id=9 project=payments requester=user#1 suggested-role=secrets-reader state=pending") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunRequestAccess_RequiresProject(t *testing.T) {
	requestAccessProject = ""
	t.Setenv("KEYORIX_PROJECT", "")
	if err := runRequestAccess(requestAccessCmd, nil); err == nil || !containsAll(err.Error(), "no project specified") {
		t.Fatalf("err = %v, want the missing-project error", err)
	}
}

// TestRunRequestList_MatchesOldCLIOutputShape matches internal/cli/request/list.go's
// runListRemote.
func TestRunRequestList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"ID":3,"Name":"payments"}]}}`)
		case r.URL.Path == "/api/v1/projects/3/access-requests" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"access_requests":[{"ID":9,"ProjectID":3,"UserID":1,"SuggestedRole":"secrets-reader","State":"pending","Reason":"onboarding"}]}}`)
		case r.URL.Path == "/api/v1/users/1" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":1,"username":"bob"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setRequestCreds(t, srv)
	requestListProject = "payments"
	defer func() { requestListProject = "" }()

	out := captureStdout(t, func() {
		if err := runRequestList(requestListCmd, nil); err != nil {
			t.Fatalf("runRequestList: %v", err)
		}
	})
	if !containsAll(out, "ID", "USER", "SUGGESTED", "9", "bob (#1)", "secrets-reader", "pending", "onboarding") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunRequestReview_SecretScopedApprove matches internal/cli/request/review.go's
// runReviewRemote secret-scoped branch.
func TestRunRequestReview_SecretScopedApprove(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"ID":3,"Name":"payments"}]}}`)
		case r.URL.Path == "/api/v1/projects/3/access-requests" && r.Method == http.MethodGet:
			secretID := 42
			_ = secretID
			_, _ = fmt.Fprint(w, `{"data":{"access_requests":[{"ID":9,"ProjectID":3,"UserID":1,"SecretID":42,"State":"pending"}]}}`)
		case r.URL.Path == "/api/v1/users/1" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":1,"username":"bob"}}`)
		case r.URL.Path == "/api/v1/secret-access-requests/9" && r.Method == http.MethodPut:
			_, _ = fmt.Fprint(w, `{"data":null}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setRequestCreds(t, srv)
	requestReviewID = 9
	requestReviewAction = "approve"
	requestReviewProject = "payments"
	requestReviewRole, requestReviewTTL, requestReviewReason = "", "", ""
	defer func() { requestReviewID, requestReviewAction, requestReviewProject = 0, "", "" }()

	out := captureStdout(t, func() {
		if err := runRequestReview(requestReviewCmd, nil); err != nil {
			t.Fatalf("runRequestReview: %v", err)
		}
	})
	if !containsAll(out, "Resolved access request 9 in project \"payments\": requester bob (#1), state=pending.",
		"Secret access request 9 approved for bob (#1) to read secret 42.") {
		t.Fatalf("output = %q", out)
	}
}

// TestRunRequestBulkApprove_MatchesOldCLIOutputShape matches
// internal/cli/request/bulk.go's printBulkApproveResult.
func TestRunRequestBulkApprove_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/access-requests/bulk-approve" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"result":{"approved":[1,2],"failed":[{"request_id":3,"error":"not found"}]}}}`)
	}))
	defer srv.Close()
	setRequestCreds(t, srv)
	requestBulkApproveIDs = "1,2,3"
	defer func() { requestBulkApproveIDs = "" }()

	out := captureStdout(t, func() {
		if err := runRequestBulkApprove(requestBulkApproveCmd, nil); err != nil {
			t.Fatalf("runRequestBulkApprove: %v", err)
		}
	})
	if !containsAll(out, "Approved 2 request(s), 1 failure(s).", "✓ request 1 approved", "✓ request 2 approved", "✗ request 3: not found") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunRejectionTemplatesList_MatchesOldCLIOutputShape matches
// internal/cli/request/bulk.go's runTmplListRemote.
func TestRunRejectionTemplatesList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rejection-reason-templates" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"templates":[{"id":1,"name":"insufficient-justification","reason":"The justification provided does not meet policy."}]}}`)
	}))
	defer srv.Close()
	setRequestCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRejectionTemplatesList(rejectionTemplatesListCmd, nil); err != nil {
			t.Fatalf("runRejectionTemplatesList: %v", err)
		}
	})
	if !containsAll(out, "id=1", "name=insufficient-justification", "reason=The justification provided does not meet policy.") {
		t.Fatalf("output = %q", out)
	}
}

func TestParseIDList_RejectsEmpty(t *testing.T) {
	if _, err := parseIDList(""); err == nil {
		t.Fatal("expected an error for an empty ID list")
	}
}

func TestParseSecretRef_RequiresThreeParts(t *testing.T) {
	if _, _, _, err := parseSecretRef("payments/production"); err == nil {
		t.Fatal("expected an error for a two-part ref")
	}
	p, e, n, err := parseSecretRef("payments/production/db-pass")
	if err != nil || p != "payments" || e != "production" || n != "db-pass" {
		t.Fatalf("parseSecretRef = (%q, %q, %q, %v)", p, e, n, err)
	}
}
