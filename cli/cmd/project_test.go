package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setProjectCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunProjectList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 6's own test requirement) against
// internal/cli/project/list.go's printProjects.
func TestRunProjectList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":1,"name":"payments","description":"Payments platform secrets"}]}}`)
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runProjectList(projectListCmd, nil); err != nil {
			t.Fatalf("runProjectList: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "DESCRIPTION", "1", "payments", "Payments platform secrets") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunProjectList_EmptyPrintsNoProjectsMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"projects":[]}}`)
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runProjectList(projectListCmd, nil); err != nil {
			t.Fatalf("runProjectList: %v", err)
		}
	})
	if !containsAll(out, "No projects found.") {
		t.Fatalf("output = %q, want the empty-state message", out)
	}
}

// TestRunProjectCreate_SeedsCustomEnvironments matches internal/cli/project/create.go's
// remote-mode body shape (the "environments" field, not "envs" -- create.go's own doc
// comment on the field-name bug this fixed on the old CLI's side).
func TestRunProjectCreate_SeedsCustomEnvironments(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":7,"name":"new-proj"}}`)
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	projectCreateName = "new-proj"
	projectCreateDesc = ""
	projectCreateEnvs = "dev,prod"
	defer func() { projectCreateName, projectCreateEnvs = "", "" }()

	out := captureStdout(t, func() {
		if err := runProjectCreate(projectCreateCmd, nil); err != nil {
			t.Fatalf("runProjectCreate: %v", err)
		}
	})
	if !containsAll(out, "Project created: id=7 name=\"new-proj\"", "Environments seeded: dev,prod") {
		t.Fatalf("output missing expected fields: %q", out)
	}
	if !containsAll(gotBody, `"environments":["dev","prod"]`) {
		t.Fatalf("request body = %q, want an \"environments\" field (not \"envs\")", gotBody)
	}
}

func TestRunProjectCreate_RequiresName(t *testing.T) {
	projectCreateName = ""
	if err := runProjectCreate(projectCreateCmd, nil); err == nil || !containsAll(err.Error(), "--name is required") {
		t.Fatalf("err = %v, want the missing-name error", err)
	}
}

// TestRunProjectDescribe_ResolvesByNameAndListsEnvironments matches
// internal/cli/project/describe.go's remote-mode output shape.
func TestRunProjectDescribe_ResolvesByNameAndListsEnvironments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"payments","description":"desc"}]}}`)
		case r.URL.Path == "/api/v1/projects/3/environments" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"environments":[{"id":10,"name":"production"}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runProjectDescribe(projectDescribeCmd, []string{"payments"}); err != nil {
			t.Fatalf("runProjectDescribe: %v", err)
		}
	})
	if !containsAll(out, "Project:      payments (id=3)", "Description:  desc", "Environments: 1", "production (id=10)") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunProjectStats_TableFormat matches internal/cli/project/stats.go's remote-mode
// table output.
func TestRunProjectStats_TableFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"payments"}]}}`)
		case r.URL.Path == "/api/v1/projects/3/stats" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"project_id":3,"project_name":"payments","total_secrets":5,"active_secrets":4,"expired_secrets":1,"unique_accessors":2,"open_anomalies":0}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setProjectCreds(t, srv)
	projectStatsFormat = "table"

	out := captureStdout(t, func() {
		if err := runProjectStats(projectStatsCmd, []string{"payments"}); err != nil {
			t.Fatalf("runProjectStats: %v", err)
		}
	})
	if !containsAll(out, "Project: payments", "Total:", "5", "Active:", "4", "Unique accessors:", "2") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunProjectHygiene_MatchesOldCLIOutputShape matches
// internal/cli/project/hygiene.go's output.
func TestRunProjectHygiene_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/3/hygiene" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"orphaned_secrets":1,"unused_secrets":2,"expiring_secrets":3,"stale_machine_identities":4,"rotation_overdue":5}}`)
	}))
	defer srv.Close()
	setProjectCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runProjectHygiene(projectHygieneCmd, []string{"3"}); err != nil {
			t.Fatalf("runProjectHygiene: %v", err)
		}
	})
	if !containsAll(out, "Hygiene for project 3:", "orphaned secrets         1", "rotation overdue         5") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunEnvClone_MatchesOldCLIOutputShape decodes core.EnvCloneResult's untagged,
// PascalCase wire shape (matches this PR's openapi.yaml doc comment on the clone route).
func TestRunEnvClone_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":3,"name":"payments"}]}}`)
		case r.URL.Path == "/api/v1/projects/3/environments" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"environments":[{"id":10,"name":"staging"},{"id":11,"name":"production"}]}}`)
		case r.URL.Path == "/api/v1/projects/3/environments/10/clone" && r.Method == http.MethodPost:
			_, _ = fmt.Fprint(w, `{"data":{"source_env":"staging","dest_env":"production","secrets_cloned":4,"secrets_skipped":1}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setProjectCreds(t, srv)
	envCloneProjectFlag = "payments"
	defer func() { envCloneProjectFlag = "" }()

	out := captureStdout(t, func() {
		if err := runEnvClone(envCloneCmd, []string{"staging", "production"}); err != nil {
			t.Fatalf("runEnvClone: %v", err)
		}
	})
	if !containsAll(out, `Cloned environment "staging" → "production"`, "Secrets cloned:  4", "Secrets skipped: 1") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunEnvDelete_RequiresConfirm matches internal/cli/project/env.go's guard.
func TestRunEnvDelete_RequiresConfirm(t *testing.T) {
	envDeleteConfirm = false
	if err := runEnvDelete(envDeleteCmd, []string{"5"}); err == nil || !containsAll(err.Error(), "--confirm") {
		t.Fatalf("err = %v, want the missing-confirm error", err)
	}
}

func TestRunEnvDelete_DeletesByBareID(t *testing.T) {
	var deletedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":null}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setProjectCreds(t, srv)
	envDeleteConfirm = true
	envProjectFlag = ""
	defer func() { envDeleteConfirm = false }()

	out := captureStdout(t, func() {
		if err := runEnvDelete(envDeleteCmd, []string{"5"}); err != nil {
			t.Fatalf("runEnvDelete: %v", err)
		}
	})
	if deletedPath != "/api/v1/environments/5" {
		t.Fatalf("deleted path = %q, want /api/v1/environments/5", deletedPath)
	}
	if !containsAll(out, "Environment 5 deleted") {
		t.Fatalf("output = %q", out)
	}
}

// TestRunProjectUse_PersistsActiveProject matches internal/cli/project/use.go's
// behavior, writing to the thin CLI's single credentials file instead of the old CLI's
// separate ~/.keyorix/cli.yaml (docs/cli-split-inventory.md §4/§7 PR 6).
func TestRunProjectUse_PersistsActiveProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"projects":[{"id":1,"name":"payments"}]}}`)
	}))
	defer srv.Close()
	setProjectCreds(t, srv)
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")

	out := captureStdout(t, func() {
		if err := runProjectUse(projectUseCmd, []string{"payments"}); err != nil {
			t.Fatalf("runProjectUse: %v", err)
		}
	})
	if !containsAll(out, `Active project set to "payments"`) {
		t.Fatalf("output = %q", out)
	}

	store, err := resolveCredStore()
	if err != nil {
		t.Fatalf("resolveCredStore: %v", err)
	}
	creds, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if creds.ActiveProject != "payments" {
		t.Fatalf("ActiveProject = %q, want %q", creds.ActiveProject, "payments")
	}
}

func TestRunProjectUse_RefusesUnknownProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"projects":[]}}`)
	}))
	defer srv.Close()
	setProjectCreds(t, srv)
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")

	err := runProjectUse(projectUseCmd, []string{"does-not-exist"})
	if err == nil || !containsAll(err.Error(), "not found") {
		t.Fatalf("err = %v, want a not-found error", err)
	}
}

func TestRunProjectCurrent_NoActiveProjectMessage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("KEYORIX_PROJECT", "")

	out := captureStdout(t, func() {
		if err := runProjectCurrent(projectCurrentCmd, nil); err != nil {
			t.Fatalf("runProjectCurrent: %v", err)
		}
	})
	if !containsAll(out, "No active project set.") {
		t.Fatalf("output = %q", out)
	}
}
