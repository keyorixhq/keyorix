package pat

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandWiring(t *testing.T) {
	names := map[string]bool{}
	for _, sub := range PATCmd.Commands() {
		names[sub.Name()] = true
	}
	for _, want := range []string{"create", "list", "revoke"} {
		assert.True(t, names[want], "missing subcommand %q", want)
	}
	assert.Contains(t, PATCmd.Aliases, "token")
	for _, f := range []string{"name", "expires", "scope", "project-id", "environment-id"} {
		assert.NotNilf(t, createCmd.Flags().Lookup(f), "create missing --%s flag", f)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestCreateAgainstMockServer(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"data":{"token":"kx_pat_rawsecret","pat":{"id":7,"name":"ci","project_scope":5,"environment_scope":3,"scopes":["secrets.read"]}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagName, flagScopes, flagProject, flagEnv, flagExpires = "ci", []string{"secrets.read"}, 5, 3, ""

	out := captureStdout(t, func() {
		require.NoError(t, createCmd.RunE(createCmd, nil))
	})

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/auth/tokens", gotPath)
	assert.Equal(t, float64(5), gotBody["project_scope"])
	assert.Equal(t, float64(3), gotBody["environment_scope"])
	assert.Equal(t, []any{"secrets.read"}, gotBody["scopes"])
	assert.Contains(t, out, "kx_pat_rawsecret", "the raw token is shown once")
	assert.Contains(t, out, "project=5 env=3 secrets.read")
}

func TestCreate_Validation(t *testing.T) {
	t.Run("name required", func(t *testing.T) {
		flagName, flagProject, flagEnv = "", 0, 0
		err := createCmd.RunE(createCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--name is required")
	})
	t.Run("env requires project", func(t *testing.T) {
		flagName, flagProject, flagEnv = "ci", 0, 4
		err := createCmd.RunE(createCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--environment-id requires --project-id")
	})
}

func TestNormalizeExpiry(t *testing.T) {
	got, err := normalizeExpiry("2026-12-31")
	require.NoError(t, err)
	assert.Equal(t, "2026-12-31T00:00:00Z", got)

	got, err = normalizeExpiry("2026-12-31T10:00:00Z")
	require.NoError(t, err)
	assert.Equal(t, "2026-12-31T10:00:00Z", got)

	_, err = normalizeExpiry("not-a-date")
	require.Error(t, err)
}

func TestDescribeScope(t *testing.T) {
	assert.Equal(t, "full access", describeScope(patView{}))
	assert.Equal(t, "project=5 env=3 secrets.read",
		describeScope(patView{ProjectScope: 5, EnvironmentScope: 3, Scopes: []string{"secrets.read"}}))
	assert.Equal(t, "secrets.read,secrets.write",
		describeScope(patView{Scopes: []string{"secrets.read", "secrets.write"}}))
}

func TestPatDate(t *testing.T) {
	assert.Equal(t, "never", patDate(nil), "absent timestamp")
	empty := ""
	assert.Equal(t, "never", patDate(&empty), "empty timestamp")
	ts := "2026-06-20T10:30:00Z"
	assert.Equal(t, "2026-06-20", patDate(&ts), "RFC3339 rendered as a compact date")
	bad := "not-a-time"
	assert.Equal(t, "not-a-time", patDate(&bad), "unparseable value passed through")
}
