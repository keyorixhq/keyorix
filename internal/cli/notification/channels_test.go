package notification

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestServer builds an httptest.Server that handles notification-channel
// routes with preconfigured JSON responses.
func buildTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *common.RemoteClient) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return srv, rc
}

const channelListBody = `{"data":{"channels":[{"id":1,"name":"slack-ops","type":"slack","enabled":true,"url":"https://hooks.slack.com/abc","email":"","events":"anomaly.detected","created_by":"admin"}]}}`
const channelSingleBody = `{"data":{"id":1,"name":"slack-ops","type":"slack","enabled":true,"url":"https://hooks.slack.com/abc","email":"","events":"anomaly.detected","created_by":"admin"}}`

func TestNotificationChannelList_Remote(t *testing.T) {
	var gotMethod, gotPath, gotAuth string

	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(channelListBody))
	})

	require.NoError(t, runChannelListRemote(rc))
	assert.Equal(t, http.MethodGet, gotMethod)
	assert.Equal(t, "/api/v1/notification-channels", gotPath)
	assert.Equal(t, "Bearer test-token", gotAuth)
}

func TestNotificationChannelAdd_Remote(t *testing.T) {
	var gotMethod, gotPath string

	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(channelSingleBody))
	})

	require.NoError(t, runChannelAddRemote(rc, "slack-ops", "slack", "https://hooks.slack.com/abc", "", "anomaly.detected"))
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/notification-channels", gotPath)
}

func TestNotificationChannelDelete_Remote(t *testing.T) {
	var methods, paths []string

	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(channelListBody))
		} else {
			_, _ = w.Write([]byte(`{"data":{"id":1,"deleted":true}}`))
		}
	})

	require.NoError(t, runChannelDeleteRemote(rc, "slack-ops"))
	assert.Contains(t, methods, http.MethodGet)
	assert.Contains(t, methods, http.MethodDelete)
	assert.Contains(t, paths, "/api/v1/notification-channels")
	assert.Contains(t, paths, "/api/v1/notification-channels/1")
}

func TestNotificationChannelUpdate_Remote(t *testing.T) {
	var methods, paths []string

	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(channelListBody))
		} else {
			_, _ = w.Write([]byte(channelSingleBody))
		}
	})

	body := map[string]interface{}{"events": "secret.rotated"}
	require.NoError(t, runChannelUpdateRemote(rc, "slack-ops", body))
	assert.Contains(t, methods, http.MethodGet)
	assert.Contains(t, methods, http.MethodPut)
	assert.Contains(t, paths, "/api/v1/notification-channels")
	assert.Contains(t, paths, "/api/v1/notification-channels/1")
}

func TestNotificationChannelList_Remote_ServerError(t *testing.T) {
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	err := runChannelListRemote(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}
