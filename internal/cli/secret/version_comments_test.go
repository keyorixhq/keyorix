package secret

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupVersionCommentRemote(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
}

func setupVersionCommentDisconnected(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "nonexistent.yaml"))
}

// ── versionCommentAddCmd ──────────────────────────────────────────────────────

func TestVersionCommentAdd_InvalidSecretID(t *testing.T) {
	err := versionCommentAddCmd.RunE(nil, []string{"abc", "7", "test comment"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestVersionCommentAdd_InvalidVersionID(t *testing.T) {
	err := versionCommentAddCmd.RunE(nil, []string{"42", "xyz", "test comment"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version ID")
}

func TestVersionCommentAdd_EmptyComment(t *testing.T) {
	setupVersionCommentRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	err := versionCommentAddCmd.RunE(nil, []string{"42", "7", ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestVersionCommentAdd_NotConnected(t *testing.T) {
	setupVersionCommentDisconnected(t)
	err := versionCommentAddCmd.RunE(nil, []string{"42", "7", "my comment"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestVersionCommentAdd_Success(t *testing.T) {
	setupVersionCommentRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/secrets/42/versions/7/comments", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"id":1,"comment":"my comment","username":"alice","created_at":"2026-06-05T12:00:00Z"}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, versionCommentAddCmd.RunE(nil, []string{"42", "7", "my comment"}))
	})
	assert.Contains(t, out, "Comment added")
	assert.Contains(t, out, "alice")
}

func TestVersionCommentAdd_ServerError(t *testing.T) {
	setupVersionCommentRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	err := versionCommentAddCmd.RunE(nil, []string{"42", "7", "my comment"})
	require.Error(t, err)
}

// ── versionCommentListCmd ────────────────────────────────────────────────────

func TestVersionCommentList_InvalidSecretID(t *testing.T) {
	err := versionCommentListCmd.RunE(nil, []string{"bad", "7"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestVersionCommentList_InvalidVersionID(t *testing.T) {
	err := versionCommentListCmd.RunE(nil, []string{"42", "bad"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version ID")
}

func TestVersionCommentList_NotConnected(t *testing.T) {
	setupVersionCommentDisconnected(t)
	err := versionCommentListCmd.RunE(nil, []string{"42", "7"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestVersionCommentList_Empty(t *testing.T) {
	setupVersionCommentRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/42/versions/7/comments", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"comments":[],"total":0}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, versionCommentListCmd.RunE(nil, []string{"42", "7"}))
	})
	assert.Contains(t, out, "No comments found")
}

func TestVersionCommentList_WithComments(t *testing.T) {
	setupVersionCommentRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"comments":[
			{"id":1,"username":"alice","comment":"first comment","created_at":"2026-01-01T00:00:00Z"},
			{"id":2,"username":"bob","comment":"second comment","created_at":"2026-02-01T00:00:00Z"}
		],"total":2}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, versionCommentListCmd.RunE(nil, []string{"42", "7"}))
	})
	assert.Contains(t, out, "2 total")
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "first comment")
	assert.Contains(t, out, "bob")
}

func TestVersionCommentList_ServerError(t *testing.T) {
	setupVersionCommentRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := versionCommentListCmd.RunE(nil, []string{"42", "7"})
	require.Error(t, err)
}

// ── versionCommentDeleteCmd ──────────────────────────────────────────────────

func TestVersionCommentDelete_InvalidSecretID(t *testing.T) {
	err := versionCommentDeleteCmd.RunE(nil, []string{"bad", "7", "1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret ID")
}

func TestVersionCommentDelete_InvalidVersionID(t *testing.T) {
	err := versionCommentDeleteCmd.RunE(nil, []string{"42", "bad", "1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version ID")
}

func TestVersionCommentDelete_InvalidCommentID(t *testing.T) {
	err := versionCommentDeleteCmd.RunE(nil, []string{"42", "7", "bad"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid comment ID")
}

func TestVersionCommentDelete_NotConnected(t *testing.T) {
	setupVersionCommentDisconnected(t)
	err := versionCommentDeleteCmd.RunE(nil, []string{"42", "7", "1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestVersionCommentDelete_Success(t *testing.T) {
	setupVersionCommentRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/secrets/42/versions/7/comments/3", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})

	out := captureStdout(t, func() {
		require.NoError(t, versionCommentDeleteCmd.RunE(nil, []string{"42", "7", "3"}))
	})
	assert.Contains(t, out, "Comment 3 deleted")
}

func TestVersionCommentDelete_ServerError(t *testing.T) {
	setupVersionCommentRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	err := versionCommentDeleteCmd.RunE(nil, []string{"42", "7", "1"})
	require.Error(t, err)
}
