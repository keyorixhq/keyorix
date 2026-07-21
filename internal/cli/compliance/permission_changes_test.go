package compliance

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const permChangePayload = `{"success":true,"data":{
	"since":"2026-06-20T00:00:00Z",
	"until":"2026-07-20T00:00:00Z",
	"changes":[
		{
			"event_id":1,
			"action":"role.assigned",
			"actor_name":"admin",
			"target_user":"alice",
			"role_name":"editor",
			"scope":"project:3",
			"changed_at":"2026-07-01T10:00:00Z"
		},
		{
			"event_id":2,
			"action":"role.removed",
			"actor_name":"admin",
			"target_user":"bob",
			"role_name":"viewer",
			"scope":"global",
			"changed_at":"2026-07-05T14:30:00Z"
		}
	],
	"total":2
}}`

// TestPermissionChangesCmd_Success — two events in the window are printed.
func TestPermissionChangesCmd_Success(t *testing.T) {
	t.Cleanup(func() {
		permChangeSince = ""
		permChangeUntil = ""
		permChangeLimit = 0
	})

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/permission-changes", r.URL.Path)
		_, _ = w.Write([]byte(permChangePayload))
	})

	out := captureStdout(t, func() {
		require.NoError(t, permissionChangesCmd.RunE(nil, nil))
	})

	assert.Contains(t, out, "Permission change audit trail")
	assert.Contains(t, out, "role.assigned")
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "editor")
	assert.Contains(t, out, "project:3")
	assert.Contains(t, out, "role.removed")
	assert.Contains(t, out, "bob")
	assert.Contains(t, out, "global")
}

// TestPermissionChangesCmd_NoEvents — empty changes array prints "No permission changes".
func TestPermissionChangesCmd_NoEvents(t *testing.T) {
	t.Cleanup(func() {
		permChangeSince = ""
		permChangeUntil = ""
		permChangeLimit = 0
	})

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"since":"2026-07-01T00:00:00Z","until":"2026-07-20T00:00:00Z","changes":[],"total":0}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, permissionChangesCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "No permission changes")
}

// TestPermissionChangesCmd_WithSinceAndUntil — since/until flags are forwarded.
func TestPermissionChangesCmd_WithSinceAndUntil(t *testing.T) {
	t.Cleanup(func() {
		permChangeSince = ""
		permChangeUntil = ""
		permChangeLimit = 0
	})
	permChangeSince = "2026-01-01T00:00:00Z"
	permChangeUntil = "2026-06-30T23:59:59Z"

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2026-01-01T00:00:00Z", r.URL.Query().Get("since"))
		assert.Equal(t, "2026-06-30T23:59:59Z", r.URL.Query().Get("until"))
		_, _ = w.Write([]byte(`{"success":true,"data":{"since":"2026-01-01T00:00:00Z","until":"2026-06-30T23:59:59Z","changes":[],"total":0}}`))
	})

	require.NoError(t, permissionChangesCmd.RunE(nil, nil))
}

// TestPermissionChangesCmd_WithLimit — limit flag is forwarded.
func TestPermissionChangesCmd_WithLimit(t *testing.T) {
	t.Cleanup(func() {
		permChangeSince = ""
		permChangeUntil = ""
		permChangeLimit = 0
	})
	permChangeLimit = 50

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "50", r.URL.Query().Get("limit"))
		_, _ = w.Write([]byte(`{"success":true,"data":{"since":"2026-06-20T00:00:00Z","until":"2026-07-20T00:00:00Z","changes":[],"total":0}}`))
	})

	require.NoError(t, permissionChangesCmd.RunE(nil, nil))
}

// TestPermissionChangesCmd_InvalidSince — bad --since returns an error before calling server.
func TestPermissionChangesCmd_InvalidSince(t *testing.T) {
	t.Cleanup(func() {
		permChangeSince = ""
		permChangeUntil = ""
		permChangeLimit = 0
	})
	permChangeSince = "not-a-date"

	setupRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		// Should never be called.
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := permissionChangesCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --since")
}

// TestPermissionChangesCmd_InvalidUntil — bad --until returns an error before calling server.
func TestPermissionChangesCmd_InvalidUntil(t *testing.T) {
	t.Cleanup(func() {
		permChangeSince = ""
		permChangeUntil = ""
		permChangeLimit = 0
	})
	permChangeUntil = "not-a-date"

	setupRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := permissionChangesCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --until")
}

// TestPermissionChangesCmd_NotConnected — no server configured → "not connected" error.
func TestPermissionChangesCmd_NotConnected(t *testing.T) {
	t.Cleanup(func() {
		permChangeSince = ""
		permChangeUntil = ""
		permChangeLimit = 0
	})
	setupDisconnected(t)

	err := permissionChangesCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestPermissionChangesCmd_ServerError — server 500 → error returned.
func TestPermissionChangesCmd_ServerError(t *testing.T) {
	t.Cleanup(func() {
		permChangeSince = ""
		permChangeUntil = ""
		permChangeLimit = 0
	})

	setupRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := permissionChangesCmd.RunE(nil, nil)
	require.Error(t, err)
}

// TestTruncate — truncate helper contracts.
func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hello", truncate("hello", 5))
	assert.Equal(t, "hell…", truncate("hello!", 5))
	assert.Equal(t, "a…", truncate("abcde", 2))
	assert.Equal(t, "", truncate("", 10))
}
