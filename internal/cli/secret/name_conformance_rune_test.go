// name_conformance_rune_test.go — exercises nameConformanceCmd.RunE directly
// (name_conformance_remote_test.go only tests the fetch helpers).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nameConformanceRuneStub(t *testing.T, path, body string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func resetNameConformanceFlags(t *testing.T) {
	t.Helper()
	orig := nameConformanceProject
	t.Cleanup(func() { nameConformanceProject = orig })
}

func TestNameConformanceCmd_NoServer(t *testing.T) {
	resetNameConformanceFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := nameConformanceCmd.RunE(nameConformanceCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestNameConformanceCmd_ProjectScoped_PolicyDisabled(t *testing.T) {
	resetNameConformanceFlags(t)
	done := nameConformanceRuneStub(t, "/api/v1/projects/4/secrets/name-conformance", `{"data":{"policy_enabled":false}}`)
	defer done()
	nameConformanceProject = 4

	out := captureStdoutForFolder(t, func() {
		err := nameConformanceCmd.RunE(nameConformanceCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No secret naming policy")
}

func TestNameConformanceCmd_ProjectScoped_NoViolations(t *testing.T) {
	resetNameConformanceFlags(t)
	done := nameConformanceRuneStub(t, "/api/v1/projects/4/secrets/name-conformance", `{"data":{"policy_enabled":true,"total_secrets":5,"violations":[]}}`)
	defer done()
	nameConformanceProject = 4

	out := captureStdoutForFolder(t, func() {
		err := nameConformanceCmd.RunE(nameConformanceCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "All 5 secret(s) conform")
}

func TestNameConformanceCmd_ProjectScoped_WithViolations(t *testing.T) {
	resetNameConformanceFlags(t)
	done := nameConformanceRuneStub(t, "/api/v1/projects/4/secrets/name-conformance",
		`{"data":{"policy_enabled":true,"total_secrets":3,"violations":[{"id":8,"name":"db-pass","type":"password","environment_id":2,"reason":"bad pattern"}]}}`)
	defer done()
	nameConformanceProject = 4

	out := captureStdoutForFolder(t, func() {
		err := nameConformanceCmd.RunE(nameConformanceCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "1 of 3 secret(s) violate")
	assert.Contains(t, out, "db-pass")
	assert.NotContains(t, out, "PROJECT")
}

func TestNameConformanceCmd_OrgWide_WithViolations(t *testing.T) {
	resetNameConformanceFlags(t)
	done := nameConformanceRuneStub(t, "/api/v1/secrets/name-conformance",
		`{"data":{"policy_enabled":true,"total_secrets":10,"violations":[{"id":8,"name":"db-pass","type":"password","environment_id":2,"reason":"bad pattern","project_name":"alpha"}]}}`)
	defer done()
	nameConformanceProject = 0

	out := captureStdoutForFolder(t, func() {
		err := nameConformanceCmd.RunE(nameConformanceCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "PROJECT")
	assert.Contains(t, out, "alpha")
	assert.Contains(t, out, "db-pass")
}

func TestNameConformanceCmd_FetchError(t *testing.T) {
	resetNameConformanceFlags(t)
	done := nameConformanceRuneStub(t, "/nonexistent", `{}`)
	defer done()
	nameConformanceProject = 4

	err := nameConformanceCmd.RunE(nameConformanceCmd, nil)
	require.Error(t, err)
}
