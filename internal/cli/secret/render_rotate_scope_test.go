// render_rotate_scope_test.go — proves (inventory #2012, finding S2) that
// `secret render` and `secret rotate` must resolve a secret name within an
// explicit (project, environment) scope, never by listing everything the
// caller can read and taking the first name match.
//
// crossScopeStub simulates the parts of the real server this depends on: two
// projects (proj-a id=10, proj-b id=20), each with its own "envX" environment
// (ids 101 and 201 — environment names are NOT globally unique, only unique
// per project) and its own secret named "db-password" (ids 1 and 2). Its
// GET /api/v1/secrets handler mirrors the real one
// (server/http/handlers/secrets_list.go): project_id/environment_id
// (numeric) are real filters; a bare `environment=<name>` query parameter is
// not a recognized filter at all and is silently ignored — an unscoped query
// returns every secret the caller can read, regardless of what `environment`
// is set to.
package secret

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func crossScopeStub(t *testing.T, rotatedID *uint) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":10,"name":"proj-a"},{"id":20,"name":"proj-b"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/10/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":101,"name":"envX"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/20/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":201,"name":"envX"}]}}`))
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("project_id") == "10" && q.Get("environment_id") == "101":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":1,"Name":"db-password"}]}}`))
		case q.Get("project_id") == "20" && q.Get("environment_id") == "201":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":2,"Name":"db-password"}]}}`))
		default:
			// No (recognized) scope filter -- e.g. a bare `environment=envX` name
			// param, which the real handler does not honor -- so the caller sees
			// every secret they can read, both same-named ones included.
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":1,"Name":"db-password"},{"ID":2,"Name":"db-password"}]}}`))
		}
	})
	mux.HandleFunc("/api/v1/secrets/1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t-a"}}`))
	})
	mux.HandleFunc("/api/v1/secrets/2", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t-b"}}`))
	})
	mux.HandleFunc("/api/v1/secrets/1/rotate", func(w http.ResponseWriter, _ *http.Request) {
		if rotatedID != nil {
			*rotatedID = 1
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	mux.HandleFunc("/api/v1/secrets/2/rotate", func(w http.ResponseWriter, _ *http.Request) {
		if rotatedID != nil {
			*rotatedID = 2
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	// Project-scoped render endpoint (server/http/handlers/secrets_render.go).
	// Each project's renderer only ever resolves its OWN project's secrets.
	mux.HandleFunc("/api/v1/projects/10/secrets/render", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"rendered":"s3cr3t-a"}}`))
	})
	mux.HandleFunc("/api/v1/projects/20/secrets/render", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"rendered":"s3cr3t-b"}}`))
	})
	return httptest.NewServer(mux)
}

// TestRunRotate_CrossProjectSameNameSecret_TargetsCorrectScope is the S2 red
// test: rotating "db-password" scoped to proj-b/envX must rotate proj-b's own
// secret (ID 2), never proj-a's same-named secret (ID 1) just because it's
// the first (or only) match an unscoped listing happens to return.
func TestRunRotate_CrossProjectSameNameSecret_TargetsCorrectScope(t *testing.T) {
	isolateCLIConfig(t)
	resetRotateFlags(t)
	require.NoError(t, rotateCmd.Flags().Set("value", "new-value"))
	require.NoError(t, rotateCmd.Flags().Set("project", "proj-b"))
	require.NoError(t, rotateCmd.Flags().Set("env", "envX"))

	var rotatedID uint
	srv := crossScopeStub(t, &rotatedID)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := runRotate(rotateCmd, []string{"db-password"})
	require.NoError(t, err)
	assert.Equal(t, uint(2), rotatedID,
		"rotate --project proj-b --env envX must rotate proj-b's own db-password (ID 2), never proj-a's same-named secret (ID 1)")
}

// TestRunRender_CrossProjectSameNameSecret_ResolvesCorrectScope is the S2 red
// test for render: ${secret:envX/db-password} scoped to --project proj-b must
// resolve proj-b's own value ("s3cr3t-b"), never proj-a's same-named secret's
// value ("s3cr3t-a").
func TestRunRender_CrossProjectSameNameSecret_ResolvesCorrectScope(t *testing.T) {
	isolateCLIConfig(t)
	origProject, origOutput := renderProjectName, renderOutput
	t.Cleanup(func() {
		renderProjectName, renderOutput = origProject, origOutput
		_ = renderCmd.Flags().Set("project", "")
		_ = renderCmd.Flags().Set("output", "")
	})
	require.NoError(t, renderCmd.Flags().Set("project", "proj-b"))

	srv := crossScopeStub(t, nil)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	dir := t.TempDir()
	tplPath := filepath.Join(dir, "tpl.txt")
	require.NoError(t, os.WriteFile(tplPath, []byte("${secret:envX/db-password}"), 0o600))
	outPath := filepath.Join(dir, "out.txt")
	require.NoError(t, renderCmd.Flags().Set("output", outPath))

	err := runRender(renderCmd, []string{tplPath})
	require.NoError(t, err)

	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t-b", string(got),
		"render --project proj-b must resolve envX/db-password against proj-b's own secret (s3cr3t-b), never proj-a's same-named secret (s3cr3t-a)")
}
