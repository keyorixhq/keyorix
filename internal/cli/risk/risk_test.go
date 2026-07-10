package risk

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

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

func TestList_Remote(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"data":{"exceptions":[]}}`))
		})
		listAll = false
		out := captureStdout(t, func() { require.NoError(t, listCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "No risk exceptions.")
	})
	t.Run("populated with --all", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "all=true", r.URL.RawQuery)
			_, _ = w.Write([]byte(`{"success":true,"data":{"exceptions":[{"id":3,"title":"legacy MFA gap","category":"mfa","reference":"user:9","justification":"migration in flight","status":"active","expires_at":"2026-12-31T00:00:00Z","approved":true}]}}`))
		})
		listAll = true
		t.Cleanup(func() { listAll = false })
		out := captureStdout(t, func() { require.NoError(t, listCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "#3 legacy MFA gap")
		assert.Contains(t, out, "approved")
		assert.Contains(t, out, "migration in flight")
	})
}

func TestAdd_Validation(t *testing.T) {
	addTitle, addJustification, addExpires = "", "", ""
	require.ErrorContains(t, addCmd.RunE(nil, nil), "--title and --justification are required")

	addTitle, addJustification = "t", "j"
	addExpires = ""
	require.ErrorContains(t, addCmd.RunE(nil, nil), "--expires is required")

	addExpires = "not-a-date"
	require.ErrorContains(t, addCmd.RunE(nil, nil), "--expires must be RFC3339")
	t.Cleanup(func() { addTitle, addJustification, addExpires = "", "", "" })
}

func TestAdd_Remote(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = w.Write([]byte(`{"success":true,"data":{"exception":{"id":11}}}`))
	})
	addTitle, addJustification = "gap", "accepted for Q3"
	addExpires = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	t.Cleanup(func() { addTitle, addJustification, addExpires = "", "", "" })
	out := captureStdout(t, func() { require.NoError(t, addCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Risk exception recorded (id=11)")
}

func TestApprove_RequiredIDAndRemote(t *testing.T) {
	approveID = 0
	require.ErrorContains(t, approveCmd.RunE(nil, nil), "--id is required")

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/risk-exceptions/4/approve", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	approveID = 4
	t.Cleanup(func() { approveID = 0 })
	out := captureStdout(t, func() { require.NoError(t, approveCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Risk exception 4 approved.")
}

func TestRevoke_RequiredIDAndRemote(t *testing.T) {
	revokeID = 0
	require.ErrorContains(t, revokeCmd.RunE(nil, nil), "--id is required")

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/risk-exceptions/4", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	revokeID = 4
	t.Cleanup(func() { revokeID = 0 })
	out := captureStdout(t, func() { require.NoError(t, revokeCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Risk exception 4 revoked.")
}
