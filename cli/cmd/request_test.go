package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
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
	requestAccessProjectID = 0
	t.Setenv("KEYORIX_PROJECT", "")
	if err := runRequestAccess(requestAccessCmd, nil); err == nil || !containsAll(err.Error(), "no project specified") {
		t.Fatalf("err = %v, want the missing-project error", err)
	}
}

// TestRunRequestAccess_ZeroGrantCallerUsesProjectID covers #2's reported case: a caller with no
// project grants is correctly denied GET /api/v1/projects (resolveRequestProjectID's backing
// call), so --project (name lookup) is unusable for them. --project-id must let them request
// access anyway, without ever calling the list-projects route.
func TestRunRequestAccess_ZeroGrantCallerUsesProjectID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet {
			t.Errorf("zero-grant caller should never hit GET /api/v1/projects, got request to %s", r.URL.Path)
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/projects/7/access-requests" && r.Method == http.MethodPost:
			_, _ = fmt.Fprint(w, `{"data":{"access_request":{"ID":11,"ProjectID":7,"UserID":2,"State":"pending"}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setRequestCreds(t, srv)
	requestAccessProject = ""
	requestAccessProjectID = 7
	requestAccessRole = ""
	requestAccessReason = ""
	defer func() { requestAccessProjectID = 0 }()

	out := captureStdout(t, func() {
		if err := runRequestAccess(requestAccessCmd, nil); err != nil {
			t.Fatalf("runRequestAccess: %v", err)
		}
	})
	if !containsAll(out, "Requesting access to project id=7", "Access requested: id=11 project=id=7 requester=user#2") {
		t.Fatalf("output missing expected fields: %q", out)
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

// ── #2360: --project-id on every project-scoped request subcommand ───────────
//
// resolveRequestProjectID's backing call (GET /api/v1/projects) is gated on a
// DEPLOYMENT-WIDE role. A caller holding no project grants -- the persona
// self-service access requests exist for -- and a reviewer whose roles.assign
// comes from a project-scoped grant are both correctly denied it, so neither can
// turn a project NAME into the ID these routes need in their URL. The three tests
// below drive each subcommand with --project-id against a server that FAILS THE
// TEST if the listing route is touched at all, which is what makes them red
// without the flag: the pre-fix code calls resolveRequestProjectID
// unconditionally.

// newNoListingServer is an httptest server that treats any request to
// GET /api/v1/projects as a test failure (the route a zero-grant caller is denied),
// and serves handler for everything else.
func newNoListingServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet {
			t.Errorf("caller without the deployment-wide listing role must never hit GET /api/v1/projects")
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
}

func TestRunRequestList_ProjectIDSkipsTheDeniedListing(t *testing.T) {
	srv := newNoListingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/projects/7/access-requests" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"access_requests":[{"ID":9,"ProjectID":7,"UserID":2,"State":"pending","Reason":"onboarding"}]}}`)
		case r.URL.Path == "/api/v1/users/2" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":2,"username":"bob"}}`)
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()
	setRequestCreds(t, srv)
	requestListProject = ""
	requestListProjectID = 7
	defer func() { requestListProjectID = 0 }()

	out := captureStdout(t, func() {
		if err := runRequestList(requestListCmd, nil); err != nil {
			t.Fatalf("runRequestList: %v", err)
		}
	})
	if !containsAll(out, "9", "bob (#2)", "pending", "onboarding") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunRequestWithdraw_ProjectIDSkipsTheDeniedListing(t *testing.T) {
	srv := newNoListingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/7/access-requests/9/withdraw" && r.Method == http.MethodPost {
			_, _ = fmt.Fprint(w, `{"data":null}`)
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()
	setRequestCreds(t, srv)
	requestWithdrawID = 9
	requestWithdrawProject = ""
	requestWithdrawProjectID = 7
	defer func() { requestWithdrawID, requestWithdrawProjectID = 0, 0 }()

	out := captureStdout(t, func() {
		if err := runRequestWithdraw(requestWithdrawCmd, nil); err != nil {
			t.Fatalf("runRequestWithdraw: %v", err)
		}
	})
	if !containsAll(out, "Withdrawing access request 9 from project id=7", "Access request 9 withdrawn.") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunRequestReview_ProjectIDSkipsTheDeniedListing(t *testing.T) {
	srv := newNoListingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/projects/7/access-requests" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"access_requests":[{"ID":9,"ProjectID":7,"UserID":2,"SuggestedRole":"project_viewer","GrantedRole":"project_viewer","State":"approved"}]}}`)
		case r.URL.Path == "/api/v1/users/2" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":2,"username":"bob"}}`)
		case r.URL.Path == "/api/v1/projects/7/access-requests/9" && r.Method == http.MethodPut:
			_, _ = fmt.Fprint(w, `{"data":null}`)
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()
	setRequestCreds(t, srv)
	requestReviewID = 9
	requestReviewAction = "approve"
	requestReviewProject = ""
	requestReviewProjectID = 7
	requestReviewRole, requestReviewTTL, requestReviewReason = "", "", ""
	defer func() { requestReviewID, requestReviewAction, requestReviewProjectID = 0, "", 0 }()

	out := captureStdout(t, func() {
		if err := runRequestReview(requestReviewCmd, nil); err != nil {
			t.Fatalf("runRequestReview: %v", err)
		}
	})
	if !containsAll(out, "Resolved access request 9 in project id=7: requester bob (#2), state=approved.",
		"Access request 9 approved: granted role \"project_viewer\" to bob (#2) permanently.") {
		t.Fatalf("output = %q", out)
	}
}

// TestRequestSubcommands_ProjectRequirementNamesBothFlags: --project is no longer
// cobra-MarkFlagRequired on withdraw/review (that would reject the --project-id-only
// invocation at parse time, before RunE ever runs). The requirement moved into RunE
// and must name both flags.
func TestRequestSubcommands_ProjectRequirementNamesBothFlags(t *testing.T) {
	t.Setenv("KEYORIX_PROJECT", "")
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"withdraw", func() error {
			requestWithdrawID, requestWithdrawProject, requestWithdrawProjectID = 9, "", 0
			return runRequestWithdraw(requestWithdrawCmd, nil)
		}},
		{"review", func() error {
			requestReviewID, requestReviewAction = 9, "approve"
			requestReviewProject, requestReviewProjectID = "", 0
			return runRequestReview(requestReviewCmd, nil)
		}},
		{"list", func() error {
			requestListProject, requestListProjectID = "", 0
			return runRequestList(requestListCmd, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil || !containsAll(err.Error(), "--project", "--project-id", "KEYORIX_PROJECT") {
				t.Fatalf("err = %v, want a missing-project error naming --project, --project-id and KEYORIX_PROJECT", err)
			}
		})
	}
	requestWithdrawID, requestReviewID, requestReviewAction = 0, 0, ""
}

// mutuallyExclusiveAnnotation is cobra's own (unexported) annotation key set by
// MarkFlagsMutuallyExclusive. Asserting its presence by literal string is the only
// way to check that wiring from outside cobra; if cobra ever renames it this test
// goes red rather than silently passing.
const mutuallyExclusiveAnnotation = "cobra_annotation_mutually_exclusive"

// TestRequestProjectFlagsWiring guards the flag wiring itself on every project-scoped
// request subcommand: both flags exist, neither is cobra-required (which would reject
// the other one's only invocation at parse time), and passing both at once is refused
// rather than silently preferring one.
//
// What it does NOT catch: the command list below is hand-written, so a NEW project-scoped
// request subcommand added without --project-id is invisible to it. It is a regression
// guard over today's four, not a completeness check over the subcommand set.
func TestRequestProjectFlagsWiring(t *testing.T) {
	for _, c := range []*cobra.Command{requestAccessCmd, requestListCmd, requestWithdrawCmd, requestReviewCmd} {
		t.Run(c.Name(), func(t *testing.T) {
			for _, f := range []string{"project", "project-id"} {
				flag := c.Flags().Lookup(f)
				if flag == nil {
					t.Fatalf("request %s: --%s is not defined", c.Name(), f)
				}
				if _, ok := flag.Annotations[cobra.BashCompOneRequiredFlag]; ok {
					t.Fatalf("request %s: --%s must not be MarkFlagRequired -- it rejects the other flag's only invocation", c.Name(), f)
				}
				if _, ok := flag.Annotations[mutuallyExclusiveAnnotation]; !ok {
					t.Fatalf("request %s: --%s is not in a mutually-exclusive group with the other project flag", c.Name(), f)
				}
			}
		})
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
