package share

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfRemove_CallsSelfShareEndpoint(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	require.NoError(t, selfRemoveCmd.RunE(selfRemoveCmd, []string{"7"}))
	assert.Equal(t, http.MethodDelete, gotMethod)
	assert.Equal(t, "/api/v1/secrets/7/self-share", gotPath, "the server identifies the caller; no user id is sent")
	assert.Equal(t, "Bearer tok", gotAuth)
}

func TestSelfRemove_InvalidID(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://example.invalid")
	t.Setenv("KEYORIX_TOKEN", "tok")
	require.ErrorContains(t, selfRemoveCmd.RunE(selfRemoveCmd, []string{"not-a-number"}), "invalid secret ID")
}

func TestSelfRemove_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound) // no such share for this caller
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	require.Error(t, selfRemoveCmd.RunE(selfRemoveCmd, []string{"7"}))
}

func TestSelfRemove_RequiresServerConnection(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.ErrorContains(t, selfRemoveCmd.RunE(selfRemoveCmd, []string{"7"}), "server connection")
}
