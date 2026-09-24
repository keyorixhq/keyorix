package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setRotCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunRotList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 1's own test requirement) against
// internal/cli/rotation/rotation.go's listCmd.
func TestRunRotList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rotation-policies" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":[{"id":1,"name":"db-rotate","scope":"project","project_id":1,"interval_days":30,"alert_days_before":7,"is_active":true}]}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRotList(rotListCmd, nil); err != nil {
			t.Fatalf("runRotList: %v", err)
		}
	})
	want := fmt.Sprintf("%-5s %-24s %-14s %-9s %-7s %s\n", "ID", "NAME", "TARGET", "INTERVAL", "ACTIVE", "ALERT") +
		fmt.Sprintf("%-5d %-24s %-14s %-9s %-7t %dd\n", 1, "db-rotate", "project=1", "30d", true, 7)
	if out != want {
		t.Fatalf("output = %q, want %q (byte-for-byte: this command matches the old CLI's own fixed-width Printf format, not cliout's tabwriter)", out, want)
	}
}

func TestRunRotList_EmptyPrintsNoPoliciesMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRotList(rotListCmd, nil); err != nil {
			t.Fatalf("runRotList: %v", err)
		}
	})
	if out != "No rotation policies.\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

func TestRunRotCreate_RequiresNameScopeAndInterval(t *testing.T) {
	rotCName, rotCScope, rotCInterval = "", "", 0
	err := runRotCreate(rotCreateCmd, nil)
	if err == nil || !containsAll(err.Error(), "--name is required") {
		t.Fatalf("err = %v, want the --name required error", err)
	}
}

func TestRunRotCreate_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rotation-policies" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"data":{"id":5,"name":"db-rotate","scope":"project","project_id":1,"interval_days":30,"alert_days_before":7}}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)
	rotCName, rotCScope, rotCProject, rotCInterval, rotCAlert, rotCNotify = "db-rotate", "project", 1, 30, 7, true
	defer func() { rotCName, rotCScope, rotCProject, rotCInterval = "", "", 0, 0 }()

	out := captureStdout(t, func() {
		if err := runRotCreate(rotCreateCmd, nil); err != nil {
			t.Fatalf("runRotCreate: %v", err)
		}
	})
	want := "Created rotation policy #5 \"db-rotate\" (project=1, every 30d, alert 7d before).\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestRunRotShow_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rotation-policies/1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":1,"name":"db-rotate","description":"desc","scope":"project","project_id":1,"interval_days":30,"alert_days_before":7,"notify_on_breach":true,"is_active":true,"created_by":"alice"}}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRotShow(rotShowCmd, []string{"1"}); err != nil {
			t.Fatalf("runRotShow: %v", err)
		}
	})
	want := "id:               1\n" +
		"name:             db-rotate\n" +
		"description:      desc\n" +
		"target:           project=1\n" +
		"interval:         30 days\n" +
		"alert before:     7 days\n" +
		"notify on breach: true\n" +
		"active:           true\n" +
		"created by:       alice\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestRunRotDelete_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setRotCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRotDelete(rotDeleteCmd, []string{"1"}); err != nil {
			t.Fatalf("runRotDelete: %v", err)
		}
	})
	if out != "Rotation policy 1 deleted.\n" {
		t.Fatalf("output = %q", out)
	}
}

// TestRunRotStatus_CallsEvaluateNotStatus is the ground-truth-vs-docs regression
// guard: docs/cli-split-inventory.md §2.4 says "status" maps to
// /rotation-policies/status, but internal/cli/rotation/rotation.go's real
// statusCmd calls /rotation-policies/evaluate -- the code is the source of
// truth (see runRotStatus's doc comment). If this ever calls /status instead,
// this test fails on the 404 from the handler below refusing anything else.
func TestRunRotStatus_CallsEvaluateNotStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rotation-policies/evaluate" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":[{"secret_id":3,"secret_name":"db-pass","project_id":1,"days_overdue":5,"is_overdue":true,"is_approaching":false}]}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRotStatus(rotStatusCmd, nil); err != nil {
			t.Fatalf("runRotStatus: %v", err)
		}
	})
	if !containsAll(out, "SECRET", "NAME", "PROJECT", "STATUS", "DAYS", "db-pass", "OVERDUE", "5 over", "1 overdue, 0 approaching.") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunRotStatus_AllWithinWindowMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRotStatus(rotStatusCmd, nil); err != nil {
			t.Fatalf("runRotStatus: %v", err)
		}
	})
	if out != "All policy-covered secrets are within their rotation window.\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestRunRotPlan_RequiresProjectIDOrAllProjects(t *testing.T) {
	rotPlanAllProjects = false
	err := runRotPlan(rotPlanCmd, nil)
	if err == nil || !containsAll(err.Error(), "provide a project id, or use --all-projects") {
		t.Fatalf("err = %v, want the missing-project-id error", err)
	}
}

func TestRunRotPlan_ProjectPlanMatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/1/rotation-plan" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"project_id":1,"total_secrets":1,"overdue_count":1,"due_soon_count":0,"waves":[{"index":0,"secrets":[{"secret_id":3,"secret_name":"db-pass","status":"overdue","days_overdue":5,"risk_score":0,"risk_band":"high","auto_rotate":false}]}]}}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)
	rotPlanAllProjects = false

	out := captureStdout(t, func() {
		if err := runRotPlan(rotPlanCmd, []string{"1"}); err != nil {
			t.Fatalf("runRotPlan: %v", err)
		}
	})
	if !containsAll(out, "Rotation plan for project 1", "1 to rotate (1 overdue, 0 due soon), 1 wave(s)", "Wave 1", "db-pass", "5d over", "high risk") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunRotPlan_AllProjectsMatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rotation-plan" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"projects_scanned":2,"projects_with_work":1,"total_secrets":1,"overdue_count":1,"due_soon_count":0,"projects":[{"project_id":1,"total_secrets":1,"overdue_count":1,"due_soon_count":0,"waves":[]}]}}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)
	rotPlanAllProjects = true
	defer func() { rotPlanAllProjects = false }()

	out := captureStdout(t, func() {
		if err := runRotPlan(rotPlanCmd, nil); err != nil {
			t.Fatalf("runRotPlan --all-projects: %v", err)
		}
	})
	if !containsAll(out, "Deployment rotation plan", "1 to rotate (1 overdue, 0 due soon) across 1 of 2 project(s)") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunRotOrder_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/1/rotation-order" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"project_id":1,"order":[{"secret_id":2,"secret_name":"root-pass"},{"secret_id":3,"secret_name":"app-pass"}]}}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRotOrder(rotOrderCmd, []string{"1"}); err != nil {
			t.Fatalf("runRotOrder: %v", err)
		}
	})
	want := "Rotation order for project 1 (rotate top to bottom):\n" +
		"   1. 2      root-pass\n" +
		"   2. 3      app-pass\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestRunRotOrder_EmptyPrintsAnyOrderMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"project_id":1,"order":[]}}`)
	}))
	defer srv.Close()
	setRotCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runRotOrder(rotOrderCmd, []string{"1"}); err != nil {
			t.Fatalf("runRotOrder: %v", err)
		}
	})
	if out != "No secret dependencies in this project — secrets can rotate in any order.\n" {
		t.Fatalf("output = %q", out)
	}
}
