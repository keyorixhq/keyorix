package breakglass

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func setupRemote(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
}

func TestBgBase(t *testing.T) {
	assert.Equal(t, "/api/v1/projects/5/break-glass", bgBase(5))
	assert.Equal(t, "/api/v1/projects/0/break-glass", bgBase(0))
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "short", truncate("short", 16))
	assert.Equal(t, "a…", truncate("abcdef", 2))
	assert.Equal(t, "a", truncate("abc", 1))
	assert.Equal(t, "", truncate("abc", 0))
}

func TestActivate_RequiredFlags(t *testing.T) {
	bgProject, bgJustify = 0, ""
	t.Cleanup(func() { bgProject, bgJustify = 0, "" })
	require.ErrorContains(t, activateCmd.RunE(nil, nil), "--project-id is required")

	bgProject = 3
	require.ErrorContains(t, activateCmd.RunE(nil, nil), "--justification is required")
}

func TestActivate_Remote(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/projects/3/break-glass", r.URL.Path)
		_, _ = w.Write([]byte(`{"success":true,"data":{"activation":{"id":7,"role_name":"break-glass-editor","expires_at":"2026-07-11T00:00:00Z"}}}`))
	})
	bgProject, bgJustify, bgTTL = 3, "prod outage #42", "2h"
	t.Cleanup(func() { bgProject, bgJustify, bgTTL = 0, "", "" })

	out := captureStdout(t, func() { require.NoError(t, activateCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Emergency access activated (id=7)")
	assert.Contains(t, out, `role "break-glass-editor"`)
}

func TestActivate_RemoteError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	bgProject, bgJustify, bgTTL = 3, "prod outage #42", "2h"
	t.Cleanup(func() { bgProject, bgJustify, bgTTL = 0, "", "" })

	err := activateCmd.RunE(nil, nil)
	require.ErrorContains(t, err, "server returned HTTP 500")
}

func TestList_Remote(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"data":{"activations":[],"count":0}}`))
		})
		bgProject = 3
		t.Cleanup(func() { bgProject = 0 })
		out := captureStdout(t, func() { require.NoError(t, listCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "No break-glass activations for project 3.")
	})

	t.Run("populated", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"data":{"count":1,"activations":[{"id":9,"user_id":2,"role_name":"break-glass-editor","state":"active","expires_at":"2026-07-11T00:00:00Z","justification":"incident"}]}}`))
		})
		bgProject = 3
		t.Cleanup(func() { bgProject = 0 })
		out := captureStdout(t, func() { require.NoError(t, listCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "Break-glass activations — project 3")
		assert.Contains(t, out, "incident")
		assert.Contains(t, out, "active")
	})
}

func TestList_RemoteError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	bgProject = 3
	t.Cleanup(func() { bgProject = 0 })

	err := listCmd.RunE(nil, nil)
	require.ErrorContains(t, err, "server returned HTTP 500")
}

func TestRevoke_RequiredFlagsAndRemote(t *testing.T) {
	bgProject, bgActivation = 0, 0
	require.ErrorContains(t, revokeCmd.RunE(nil, nil), "required")

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/projects/3/break-glass/9/revoke", r.URL.Path)
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	})
	bgProject, bgActivation = 3, 9
	t.Cleanup(func() { bgProject, bgActivation = 0, 0 })
	out := captureStdout(t, func() { require.NoError(t, revokeCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Revoked break-glass activation 9 in project 3.")
}

func TestRevoke_RemoteError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	bgProject, bgActivation = 3, 9
	t.Cleanup(func() { bgProject, bgActivation = 0, 0 })

	err := revokeCmd.RunE(nil, nil)
	require.ErrorContains(t, err, "server returned HTTP 500")
}
