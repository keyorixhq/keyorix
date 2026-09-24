package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setAccessReviewCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunAccessReview_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 7's own test requirement) against
// internal/cli/accessreview/accessreview.go's AccessReviewCmd.RunE.
func TestRunAccessReview_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/3/access-review" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"entries":[{"principal_type":"user","principal_id":1,"principal_name":"alice","email":"alice@example.com","source":"role","role_id":2,"role_name":"secrets-admin","access_level":"write","environment_id":0,"last_used_at":null}],"count":1}}`)
	}))
	defer srv.Close()
	setAccessReviewCreds(t, srv)
	accessReviewProject = 3
	defer func() { accessReviewProject = 0 }()

	out := captureStdout(t, func() {
		if err := runAccessReview(accessReviewCmd, nil); err != nil {
			t.Fatalf("runAccessReview: %v", err)
		}
	})
	if !containsAll(out, "Access review — project 3 (1 grant(s)):", "SOURCE", "role", "user", "alice <alice@example.co", "write", "role=secrets-admin (project)") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunAccessReview_RequiresProjectID(t *testing.T) {
	accessReviewProject = 0
	if err := runAccessReview(accessReviewCmd, nil); err == nil || !containsAll(err.Error(), "--project-id is required") {
		t.Fatalf("err = %v, want the missing-project-id error", err)
	}
}

// TestRunAccessReviewCampaignOpen_MatchesOldCLIOutputShape matches
// internal/cli/accessreview/campaign.go's campaignOpenCmd.
func TestRunAccessReviewCampaignOpen_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/3/access-review/campaigns" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"campaign":{"id":7,"project_id":3,"name":"Q4 recert","state":"open"},"progress":{"total":5,"pending":5,"attested":0,"revoked":0}}}`)
	}))
	defer srv.Close()
	setAccessReviewCreds(t, srv)
	campaignProject = 3
	campaignName = "Q4 recert"
	defer func() { campaignProject, campaignName = 0, "" }()

	out := captureStdout(t, func() {
		if err := accessReviewCampaignOpenCmd.RunE(accessReviewCampaignOpenCmd, nil); err != nil {
			t.Fatalf("campaign open: %v", err)
		}
	})
	if !containsAll(out, `Opened campaign 7 ("Q4 recert") for project 3`, "5 total — 5 pending, 0 attested, 0 revoked") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}
