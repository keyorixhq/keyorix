package legalhold

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatusCmd_ActiveHold tests that statusCmd prints the hold details when active.
func TestStatusCmd_ActiveHold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/legal-hold", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"active":true,"hold":{"id":3,"reason":"litigation-xyz","placed_by":1,"placed_at":"2026-07-01T10:00:00Z"}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	require.NoError(t, statusCmd.RunE(statusCmd, nil))
}

// TestStatusCmd_NoHold tests that statusCmd prints the "no hold" message when inactive.
func TestStatusCmd_NoHold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"active":false,"hold":{}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	require.NoError(t, statusCmd.RunE(statusCmd, nil))
}

// TestStatusCmd_ServerError verifies statusCmd surfaces HTTP errors.
func TestStatusCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	err := statusCmd.RunE(statusCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestPlaceCmd_Happy tests that placeCmd POSTs the reason and succeeds.
func TestPlaceCmd_Happy(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		_, _ = w.Write([]byte(`{"data":{"hold":{"id":5,"reason":"legal-abc","placed_by":1,"placed_at":"2026-07-01T12:00:00Z"}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origReason := placeReason
	defer func() { placeReason = origReason }()
	placeReason = "legal-abc"

	require.NoError(t, placeCmd.RunE(placeCmd, nil))
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/legal-hold", gotPath)
	assert.Contains(t, gotBody, "legal-abc")
}

// TestPlaceCmd_ServerError verifies placeCmd surfaces HTTP errors.
func TestPlaceCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origReason := placeReason
	defer func() { placeReason = origReason }()
	placeReason = "test reason"

	err := placeCmd.RunE(placeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// TestStatusCmd_NotConnected verifies statusCmd fails gracefully when no server configured.
func TestStatusCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := statusCmd.RunE(statusCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestPlaceCmd_NotConnected verifies placeCmd fails gracefully when no server configured.
func TestPlaceCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	origReason := placeReason
	defer func() { placeReason = origReason }()
	placeReason = "test"

	err := placeCmd.RunE(placeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}
