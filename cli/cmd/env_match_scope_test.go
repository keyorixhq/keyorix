package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// envCaseServer serves a project holding BOTH "prod" (id 1) and "Prod" (id 2), each with
// one secret, and records the environment_id every secret list asked for. The server
// allows this pair: environment uniqueness is case-sensitive.
func envCaseServer(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/environments"):
			_, _ = fmt.Fprint(w, `{"data":{"environments":[{"id":1,"name":"prod"},{"id":2,"name":"Prod"}]}}`)
		case r.URL.Path == "/api/v1/secrets" && r.Method == http.MethodGet:
			env := r.URL.Query().Get("environment_id")
			mu.Lock()
			asked = append(asked, env)
			mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"data":{"secrets":[{"id":1%s,"name":"k"}]}}`, env)
		case strings.HasPrefix(r.URL.Path, "/api/v1/secrets/") && r.URL.Query().Get("include_value") == "true":
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
			_, _ = fmt.Fprintf(w, `{"data":{"id":%s,"value":"v%s"}}`, id, id)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	setRequestCreds(t, srv)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

// `keyorix run --env Prod` must read environment 2 ("Prod"), not environment 1 ("prod")
// just because that one is listed first; reading the wrong environment would inject its
// secrets into the child process.
func TestFetchRunSecrets_ExactEnvironmentNameWinsOverCaseFold(t *testing.T) {
	asked := envCaseServer(t)
	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	got, err := fetchRunSecrets(context.Background(), client, 1, "p", "Prod", nil)
	if err != nil {
		t.Fatalf("fetchRunSecrets: %v", err)
	}
	if a := asked(); len(a) == 0 || a[0] != "2" {
		t.Fatalf("listed secrets of environment_id %v, want 2 (\"Prod\")", a)
	}
	if got["k"] != "v12" {
		t.Fatalf("injected %v, want k=v12 from environment 2", got)
	}
}

// A name that folds to both environments and is exactly neither is refused before any
// secret is listed or read.
func TestFetchRunSecrets_AmbiguousEnvironmentNameReadsNothing(t *testing.T) {
	asked := envCaseServer(t)
	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	got, err := fetchRunSecrets(context.Background(), client, 1, "p", "PROD", nil)
	if err == nil {
		t.Fatalf("fetchRunSecrets resolved an ambiguous environment name, injected %v", got)
	}
	if a := asked(); len(a) != 0 {
		t.Fatalf("listed secrets for environment_id %v after an ambiguous name; want none", a)
	}
}

// A project holding both "Development" and "development": the default environment of
// `secret create` is the exact "development", whichever is listed first, never the other.
func TestDefaultEnvironmentForProject_ExactDevelopmentWinsOverCaseFold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/projects/2/environments" {
			_, _ = fmt.Fprint(w, `{"data":{"environments":[{"id":8,"name":"Development"},{"id":9,"name":"development"}]}}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	setPATCreds(t, srv)
	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	id, ok, err := defaultEnvironmentForProject(context.Background(), client, 2)
	if err != nil || !ok || id != 9 {
		t.Fatalf("got id=%d ok=%v err=%v; want id 9 (\"development\")", id, ok, err)
	}
}

// Two environments that fold to "development" and neither is exact: refuse and ask for
// --environment instead of writing the secret into whichever is listed first.
func TestDefaultEnvironmentForProject_AmbiguousFoldRequiresExplicitEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/projects/2/environments" {
			_, _ = fmt.Fprint(w, `{"data":{"environments":[{"id":8,"name":"Development"},{"id":9,"name":"DEVELOPMENT"}]}}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	setPATCreds(t, srv)
	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	id, ok, err := defaultEnvironmentForProject(context.Background(), client, 2)
	if err == nil || !strings.Contains(err.Error(), "--environment is required") {
		t.Fatalf("got id=%d ok=%v err=%v; want an error asking for --environment", id, ok, err)
	}
}
