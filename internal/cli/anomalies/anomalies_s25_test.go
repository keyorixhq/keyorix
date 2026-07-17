package anomalies

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunList_Connected exercises the success branch of runList (line 61:
// return runListRemote(rc)), which is only reachable when NewRemoteClient
// returns ok=true. The existing stub tests call runListRemote directly and
// therefore leave that branch uncovered.
func TestRunList_Connected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"alerts":[],"total":0}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	err := runList(listCmd, nil)
	require.NoError(t, err)
}

// TestRunList_Connected_WithAlerts exercises the success branch of runList
// when the server returns a populated alert list, ensuring both the
// NewRemoteClient success path and the alert-printing loop are exercised
// together through the top-level command handler.
func TestRunList_Connected_WithAlerts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"alerts":[
			{"ID":3,"SecretName":"db","AlertType":"new_ip","Severity":"high","Description":"test","AccessedBy":"bob","IPAddress":"10.0.0.2","DetectedAt":"2026-07-14T12:00:00Z","Acknowledged":false}
		],"total":1}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	err := runList(listCmd, nil)
	require.NoError(t, err)
}

// TestRunAcknowledge_Connected exercises the success branch of runAcknowledge
// (line 100: return runAcknowledgeRemote(rc, id)), which requires a valid
// numeric ID and NewRemoteClient returning ok=true. The existing stub tests
// call runAcknowledgeRemote directly and leave this branch uncovered.
func TestRunAcknowledge_Connected(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"acknowledged":true}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	err := runAcknowledge(acknowledgeCmd, []string{"42"})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/audit/anomalies/42/acknowledge", gotPath)
}

// TestRunAcknowledge_InvalidID_s25 guards the invalid-ID branch of
// runAcknowledge (line 93-95) — ParseUint must reject non-numeric input
// before any network call is attempted.
func TestRunAcknowledge_InvalidID_s25(t *testing.T) {
	err := runAcknowledge(acknowledgeCmd, []string{"abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid alert ID")
	assert.Contains(t, err.Error(), "abc")
}
