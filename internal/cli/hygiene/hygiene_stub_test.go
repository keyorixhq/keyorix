package hygiene

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHygieneCmd_RunE_HappyPath tests the full HygieneCmd.RunE body against a stub.
func TestHygieneCmd_RunE_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/hygiene", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"totals":{"orphaned_secrets":1,"unused_secrets":2},"projects":[]}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origU, origE, origS := unusedDays, expiringDays, staleDays
	defer func() { unusedDays = origU; expiringDays = origE; staleDays = origS }()
	unusedDays, expiringDays, staleDays = 0, 0, 0

	require.NoError(t, HygieneCmd.RunE(HygieneCmd, nil))
}

// TestHygieneCmd_RunE_WithWindows tests the RunE body passes non-zero windows.
func TestHygieneCmd_RunE_WithWindows(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":{"totals":{},"projects":[]}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origU, origE, origS := unusedDays, expiringDays, staleDays
	defer func() { unusedDays = origU; expiringDays = origE; staleDays = origS }()
	unusedDays, expiringDays, staleDays = 60, 14, 45

	require.NoError(t, HygieneCmd.RunE(HygieneCmd, nil))
	assert.Contains(t, gotQuery, "unused_days=60")
	assert.Contains(t, gotQuery, "expiring_days=14")
	assert.Contains(t, gotQuery, "stale_days=45")
}

// TestHygieneCmd_RunE_NotConnected verifies the command fails gracefully with no server.
func TestHygieneCmd_RunE_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := HygieneCmd.RunE(HygieneCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestHygieneCmd_RunE_ServerError verifies HTTP errors are surfaced.
func TestHygieneCmd_RunE_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	err := HygieneCmd.RunE(HygieneCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}
