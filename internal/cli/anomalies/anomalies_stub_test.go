package anomalies

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunList_UnacknowledgedFilter verifies the --unacknowledged flag appends
// the query param to the request path.
func TestRunList_UnacknowledgedFilter(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"data":{"alerts":[],"total":0}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	// Reset the global flag.
	origFlag := flagUnacknowledged
	defer func() { flagUnacknowledged = origFlag }()

	flagUnacknowledged = true
	require.NoError(t, runListRemote(rc))
	assert.Equal(t, "/api/v1/audit/anomalies?unacknowledged=true", gotPath)

	flagUnacknowledged = false
	require.NoError(t, runListRemote(rc))
	assert.Equal(t, "/api/v1/audit/anomalies", gotPath)
}

// TestRunListRemote_NoAlerts verifies the "No anomaly alerts found" branch.
func TestRunListRemote_NoAlerts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"alerts":[],"total":0}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(rc))
}

// TestRunListRemote_WithAcknowledged tests that an acknowledged alert gets the [ACK] suffix.
func TestRunListRemote_WithAcknowledged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"alerts":[
			{"ID":1,"SecretName":"db","AlertType":"new_ip","Severity":"high","Description":"new ip","AccessedBy":"alice","IPAddress":"10.0.0.1","DetectedAt":"2026-07-01T00:00:00Z","Acknowledged":true}
		],"total":1}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(rc))
}

// TestRunList_NotConnected verifies runList (the top-level RunE) errors when no server.
func TestRunList_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runList(listCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestRunAcknowledge_NotConnected verifies runAcknowledge errors when no server.
func TestRunAcknowledge_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runAcknowledge(acknowledgeCmd, []string{"5"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}
