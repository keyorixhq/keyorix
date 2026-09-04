// audit_rune_test.go — exercises auditCmd.RunE directly
// (audit_remote_test.go only tests fetchAuditTrail).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetAuditFlags(t *testing.T) {
	t.Helper()
	origID, origLimit := auditID, auditLimit
	t.Cleanup(func() { auditID = origID; auditLimit = origLimit })
}

func TestAuditCmd_MissingID(t *testing.T) {
	resetAuditFlags(t)
	auditID = 0
	err := auditCmd.RunE(auditCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestAuditCmd_NoServer(t *testing.T) {
	resetAuditFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	auditID = 7
	err := auditCmd.RunE(auditCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestAuditCmd_Success_Empty(t *testing.T) {
	resetAuditFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"audit":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	auditID = 7

	out := captureStdoutForFolder(t, func() {
		err := auditCmd.RunE(auditCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No audit events")
}

func TestAuditCmd_Success_WithLimitAndRows(t *testing.T) {
	resetAuditFlags(t)
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"audit":[{"event_type":"rotated","timestamp":"2026-01-01T00:00:00Z","actor_type":"human","description":"rotated by alice"}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	auditID = 7
	auditLimit = 5

	out := captureStdoutForFolder(t, func() {
		err := auditCmd.RunE(auditCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, gotQuery, "limit=5")
	assert.Contains(t, out, "rotated by alice")
}

func TestAuditCmd_FetchError(t *testing.T) {
	resetAuditFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	auditID = 7

	err := auditCmd.RunE(auditCmd, nil)
	require.Error(t, err)
}
