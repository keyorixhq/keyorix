package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestResolveRunProjectID_UsesProjectIDWithoutListingProjects covers the same
// shape as request_test.go's TestRunRequestAccess_ZeroGrantCallerUsesProjectID
// (#2360) for `keyorix run`: a project-scoped machine token -- the usual
// caller of `run` in a CI/service context -- is correctly denied GET
// /api/v1/projects (it needs a GLOBAL secrets.read grant the token never
// holds), so --project (name lookup) is unusable for it. --project-id must
// resolve without ever calling that route.
func TestResolveRunProjectID_UsesProjectIDWithoutListingProjects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet {
			t.Errorf("a caller using --project-id should never hit GET /api/v1/projects, got request to %s", r.URL.Path)
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setRequestCreds(t, srv)

	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	id, label, err := resolveRunProjectID(context.Background(), client, 42, "")
	if err != nil {
		t.Fatalf("resolveRunProjectID: %v", err)
	}
	if id != 42 || label != "id=42" {
		t.Fatalf("resolveRunProjectID(42, \"\") = (%d, %q), want (42, \"id=42\")", id, label)
	}
}

// TestResolveRunProjectID_ResolvesByName is the non-regression case: a caller
// with list-projects access still resolves --project by name exactly as
// before this change.
func TestResolveRunProjectID_ResolvesByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/projects" && r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, `{"data":{"projects":[{"ID":3,"Name":"payments"}]}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setRequestCreds(t, srv)

	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	id, label, err := resolveRunProjectID(context.Background(), client, 0, "payments")
	if err != nil {
		t.Fatalf("resolveRunProjectID: %v", err)
	}
	if id != 3 || label != "payments" {
		t.Fatalf("resolveRunProjectID(0, \"payments\") = (%d, %q), want (3, \"payments\")", id, label)
	}
}

// TestResolveRunProjectID_NameNotFound is the existing not-found error path,
// unchanged by this fix.
func TestResolveRunProjectID_NameNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"projects":[]}}`)
	}))
	defer srv.Close()
	setRequestCreds(t, srv)

	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	_, _, err = resolveRunProjectID(context.Background(), client, 0, "nope")
	if err == nil || !containsAll(err.Error(), `project "nope" not found`) {
		t.Fatalf("resolveRunProjectID: err = %v, want a not-found error naming the project", err)
	}
}
