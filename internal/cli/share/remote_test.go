package share

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/require"
)

// TestRunCreateRemote is the #G66 regression: `share create` previously had
// no remote/local dispatch at all (unlike every sibling command in this
// package) and always wrote to embedded storage, silently no-opping even
// when connected to a real server. Confirms runCreateRemote actually reaches
// POST /api/v1/secrets/{id}/share.
func TestRunCreateRemote(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/secrets/7/share", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		_, _ = w.Write([]byte(`{"data":{
			"ID":1,"SecretID":7,"OwnerID":1,"RecipientID":5,"IsGroup":false,"Permission":"read","CreatedAt":"2026-06-08T10:00:00Z"
		}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runCreateRemote(rc, 7, 5, false, "read", nil))
}

func TestShareReadRemote(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/secrets/7/shares", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		_, _ = w.Write([]byte(`{"data":{"shares":[
			{"ID":1,"SecretID":7,"OwnerID":1,"RecipientID":5,"IsGroup":false,"Permission":"read","CreatedAt":"2026-06-08T10:00:00Z"}
		]}}`))
	})
	mux.HandleFunc("/api/v1/shared-secrets", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		_, _ = w.Write([]byte(`{"data":{"secrets":[
			{"ID":7,"Name":"db-pass","Type":"password","ProjectID":1,"EnvironmentID":1,"CreatedBy":"admin","CreatedAt":"2026-06-08T10:00:00Z"}
		]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(rc, 7))
	require.NoError(t, runSharedSecretsRemote(rc, 0))
}

// TestRunSharedSecretsRemote_UserID_RoutesThroughAdminScopedPath asserts that a
// non-zero --user-id targets the admin-scoped GET /api/v1/users/{id}/shared-secrets
// route rather than the caller-scoped GET /api/v1/shared-secrets — previously
// --user-id was silently ignored in remote mode (CLI-split inventory §6).
func TestRunSharedSecretsRemote_UserID_RoutesThroughAdminScopedPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runSharedSecretsRemote(rc, 42))
	require.Equal(t, "/api/v1/users/42/shared-secrets", gotPath)
}
