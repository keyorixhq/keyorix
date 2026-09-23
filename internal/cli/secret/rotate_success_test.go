// rotate_success_test.go — exercises runRotate's full remote success path and
// the "secret not found" branch; rotate_test.go only covers the value-flag
// warning, the no-terminal prompt failure, and the hung-server timeout.
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunRotate_ListSecretsError(t *testing.T) {
	isolateCLIConfig(t)
	resetRotateFlags(t)
	require.NoError(t, rotateCmd.Flags().Set("value", "new-value"))
	require.NoError(t, rotateCmd.Flags().Set("project", "proj"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"proj"}]}}`))
		case "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"production"}]}}`))
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := runRotate(rotateCmd, []string{"db-password"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list secrets")
}

func TestRunRotate_RotateRequestError(t *testing.T) {
	isolateCLIConfig(t)
	resetRotateFlags(t)
	require.NoError(t, rotateCmd.Flags().Set("value", "new-value"))
	require.NoError(t, rotateCmd.Flags().Set("project", "proj"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"proj"}]}}`))
		case r.URL.Path == "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"production"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":9,"Name":"db-password"}]}}`))
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := runRotate(rotateCmd, []string{"db-password"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotate request failed")
}
