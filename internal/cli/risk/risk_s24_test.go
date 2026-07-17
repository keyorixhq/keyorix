package risk

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestList_NotConnected covers the listCmd.RunE path when KEYORIX_SERVER is unset.
func TestList_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	listAll = false
	err := listCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestList_PendingApproval verifies that exceptions with Approved=false are shown as "pending approval".
func TestList_PendingApproval(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"exceptions":[{"id":7,"title":"SoD gap","category":"sod","reference":"","justification":"owner notified","status":"active","expires_at":"2027-01-01T00:00:00Z","approved":false}]}}`))
	})
	listAll = false
	out := captureStdout(t, func() { require.NoError(t, listCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "#7 SoD gap")
	assert.Contains(t, out, "pending approval")
}

// TestAdd_NotConnected covers addCmd.RunE when validation passes but no server is configured.
func TestAdd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	addTitle = "gap"
	addJustification = "j"
	addExpires = "2026-12-31T00:00:00Z"
	t.Cleanup(func() { addTitle, addJustification, addExpires = "", "", "" })
	err := addCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestApprove_NotConnected covers approveCmd.RunE when the ID is set but no server is configured.
func TestApprove_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	approveID = 5
	t.Cleanup(func() { approveID = 0 })
	err := approveCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestRevoke_NotConnected covers revokeCmd.RunE when the ID is set but no server is configured.
func TestRevoke_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	revokeID = 5
	t.Cleanup(func() { revokeID = 0 })
	err := revokeCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}
