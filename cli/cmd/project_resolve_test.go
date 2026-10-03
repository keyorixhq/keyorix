package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// scopedProjectServer models the server's real authorization for #2562: GET
// /api/v1/projects is GLOBAL-secrets.read only (403 for a project-scoped
// caller), GET /api/v1/projects/{id} is authorized per project -- 200 only for
// the one project the caller holds a grant on, 403 for every other ID. It
// records which paths were hit.
func scopedProjectServer(t *testing.T, globalList bool) (*apiclient.ClientWithResponses, *[]string) {
	t.Helper()
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/projects":
			if !globalList {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"Forbidden","message":"Insufficient permissions"}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":2,"name":"backend-api"},{"id":3,"name":"payments"}]}}`))
		case "/api/v1/projects/2":
			_, _ = w.Write([]byte(`{"data":{"id":2,"name":"backend-api","description":"granted"}}`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Forbidden","message":"Insufficient permissions"}`))
		}
	}))
	t.Cleanup(srv.Close)
	client, err := newAPIClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	return client, &hits
}

// TestResolveProjectRef_ScopedCallerResolvesGrantedProjectByID is #2562's
// core case: the global listing 403s, and the numeric reference resolves
// through the per-project read instead.
func TestResolveProjectRef_ScopedCallerResolvesGrantedProjectByID(t *testing.T) {
	client, _ := scopedProjectServer(t, false)
	name, id, err := resolveProjectRef(context.Background(), client, "2", false)
	if err != nil {
		t.Fatalf("resolveProjectRef(\"2\") as a scoped caller: %v", err)
	}
	if id != 2 || name != "backend-api" {
		t.Fatalf("resolveProjectRef(\"2\") = (%q, %d), want (\"backend-api\", 2)", name, id)
	}
}

// TestResolveProjectRef_ScopedCallerCannotResolveUngrantedProject: the
// fallback must surface the server's per-project denial, never turn a 403
// into a resolved ID.
func TestResolveProjectRef_ScopedCallerCannotResolveUngrantedProject(t *testing.T) {
	client, _ := scopedProjectServer(t, false)
	_, id, err := resolveProjectRef(context.Background(), client, "3", false)
	if err == nil {
		t.Fatalf("resolveProjectRef(\"3\") for an ungranted project resolved to id %d, want an error", id)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("want the server's 403 surfaced, got: %v", err)
	}
}

// TestResolveProjectRef_ScopedCallerNameGetsGuidanceAndNoProbe: a name cannot
// be resolved without a listing the caller may see; no per-project request is
// made for it, and the error names the numeric-ID form.
func TestResolveProjectRef_ScopedCallerNameGetsGuidanceAndNoProbe(t *testing.T) {
	client, hits := scopedProjectServer(t, false)
	_, _, err := resolveProjectRef(context.Background(), client, "backend-api", false)
	if err == nil || !strings.Contains(err.Error(), "numeric ID") {
		t.Fatalf("want guidance naming the numeric-ID form, got: %v", err)
	}
	for _, h := range *hits {
		if h != "/api/v1/projects" {
			t.Fatalf("a name reference must not trigger any per-project request, saw %s", h)
		}
	}
}

// TestResolveProjectRef_GlobalCallerUnchanged: an admin-tier caller still
// resolves by name through the listing (exact vs folded per caller) and never
// touches the per-project fallback.
func TestResolveProjectRef_GlobalCallerUnchanged(t *testing.T) {
	client, hits := scopedProjectServer(t, true)
	if _, id, err := resolveProjectRef(context.Background(), client, "payments", false); err != nil || id != 3 {
		t.Fatalf("exact name: got (%d, %v), want (3, nil)", id, err)
	}
	if _, _, err := resolveProjectRef(context.Background(), client, "PAYMENTS", false); err == nil {
		t.Fatalf("exact-match caller resolved a case-folded name; want not found")
	}
	if _, id, err := resolveProjectRef(context.Background(), client, "PAYMENTS", true); err != nil || id != 3 {
		t.Fatalf("folded name: got (%d, %v), want (3, nil)", id, err)
	}
	if name, id, err := resolveProjectRef(context.Background(), client, "3", false); err != nil || id != 3 || name != "payments" {
		t.Fatalf("numeric ref via listing: got (%q, %d, %v), want (\"payments\", 3, nil)", name, id, err)
	}
	for _, h := range *hits {
		if h != "/api/v1/projects" {
			t.Fatalf("a caller the listing serves must never use the per-project fallback, saw %s", h)
		}
	}
}

// TestResolveProjectRef_NonForbiddenListingErrorDoesNotFallBack: only a 403
// (the caller lacks the global role) opens the fallback; any other listing
// failure stays an error.
func TestResolveProjectRef_NonForbiddenListingErrorDoesNotFallBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects" {
			t.Errorf("unexpected fallback request to %s after a non-403 listing failure", r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	client, err := newAPIClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	if _, _, err := resolveProjectRef(context.Background(), client, "2", false); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want the listing's HTTP 500 surfaced, got: %v", err)
	}
}
