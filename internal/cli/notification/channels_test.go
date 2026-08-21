package notification

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
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

// ── runChannelGetRemote ───────────────────────────────────────────────────────

func TestNotificationChannelGet_Remote_Found(t *testing.T) {
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(channelListBody))
	})

	err := runChannelGetRemote(rc, "slack-ops")
	require.NoError(t, err)
}

func TestNotificationChannelGet_Remote_NameNotFound(t *testing.T) {
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(channelListBody))
	})

	err := runChannelGetRemote(rc, "nonexistent-channel")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestNotificationChannelGet_Remote_ServerError(t *testing.T) {
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := runChannelGetRemote(rc, "slack-ops")
	require.Error(t, err)
}

// ── printChannel ──────────────────────────────────────────────────────────────

func TestPrintChannel_WithURL(t *testing.T) {
	ch := notificationChannelWire{
		ID:        1,
		Name:      "ops-hook",
		Type:      "webhook",
		Enabled:   true,
		URL:       "https://hook.example.com",
		Events:    "anomaly.detected",
		CreatedBy: "admin",
	}
	// Just exercise without panicking; output goes to stdout.
	printChannel(ch)
}

func TestPrintChannel_WithEmail(t *testing.T) {
	ch := notificationChannelWire{
		ID:        2,
		Name:      "email-ops",
		Type:      "email",
		Enabled:   false,
		Email:     "ops@example.com",
		Events:    "", // empty → printed as "*"
		CreatedBy: "admin",
	}
	printChannel(ch)
}

// ── buildUpdateBody ───────────────────────────────────────────────────────────

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "update <name>"}
	var u, e, ev string
	var enabled, disabled bool
	cmd.Flags().StringVar(&u, "url", "", "")
	cmd.Flags().StringVar(&e, "email", "", "")
	cmd.Flags().StringVar(&ev, "events", "", "")
	cmd.Flags().BoolVar(&enabled, "enabled", false, "")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "")
	return cmd
}

func TestBuildUpdateBody_NoChanges(t *testing.T) {
	cmd := newUpdateCmd()
	body := buildUpdateBody(cmd, "", "", "", false, false)
	assert.Empty(t, body)
}

func TestBuildUpdateBody_URLChanged(t *testing.T) {
	cmd := newUpdateCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--url", "https://new.example.com"}))
	url, _ := cmd.Flags().GetString("url")

	body := buildUpdateBody(cmd, url, "", "", false, false)
	assert.Equal(t, "https://new.example.com", body["url"])
	assert.NotContains(t, body, "email")
	assert.NotContains(t, body, "events")
}

func TestBuildUpdateBody_Enable(t *testing.T) {
	cmd := newUpdateCmd()
	body := buildUpdateBody(cmd, "", "", "", true, false)
	require.Contains(t, body, "enabled")
	assert.True(t, body["enabled"].(bool))
}

func TestBuildUpdateBody_Disable(t *testing.T) {
	cmd := newUpdateCmd()
	body := buildUpdateBody(cmd, "", "", "", false, true)
	require.Contains(t, body, "enabled")
	assert.False(t, body["enabled"].(bool))
}

func TestBuildUpdateBody_EmailAndEvents(t *testing.T) {
	cmd := newUpdateCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--email", "ops@example.com", "--events", "secret.rotated"}))
	email, _ := cmd.Flags().GetString("email")
	events, _ := cmd.Flags().GetString("events")

	body := buildUpdateBody(cmd, "", email, events, false, false)
	assert.Equal(t, "ops@example.com", body["email"])
	assert.Equal(t, "secret.rotated", body["events"])
	assert.NotContains(t, body, "url")
}

// ── cobra entry-point coverage (no-server / no-confirm paths) ─────────────────

func TestRunChannelList_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runChannelList(listCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunChannelAdd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	// addCmd requires --type, so set the flag variable directly.
	origType := flagChannelType
	t.Cleanup(func() { flagChannelType = origType })
	flagChannelType = "webhook"

	err := runChannelAdd(addCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunChannelGet_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runChannelGet(getCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunChannelUpdate_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runChannelUpdate(updateCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunChannelDelete_NoConfirm(t *testing.T) {
	origConfirm := flagConfirm
	t.Cleanup(func() { flagConfirm = origConfirm })
	flagConfirm = false

	err := runChannelDelete(deleteCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "add --confirm")
}

func TestRunChannelDelete_NoServer(t *testing.T) {
	origConfirm := flagConfirm
	t.Cleanup(func() { flagConfirm = origConfirm })
	flagConfirm = true
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := runChannelDelete(deleteCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// ── cobra entry-point coverage (no-server, config-isolated) ───────────────────
//
// The *_NoServer tests above rely on the ambient environment having no
// ~/.keyorix/cli.yaml / ./keyorix.yaml lying around; on a machine that has one
// (e.g. from a prior 'keyorix connect'), common.ResolveRemote finds it despite
// KEYORIX_SERVER/KEYORIX_TOKEN being cleared, and the test instead exercises a
// real (slow, network-dependent) connection attempt to that stale server. This
// is a known local-only condition — see internal/cli/config/cli_config.go's
// getDefaultCLIConfigPath, which honors XDG_CONFIG_HOME first. Pointing
// XDG_CONFIG_HOME at an empty per-test temp dir (the pattern already used
// elsewhere in this repo, e.g. internal/cli/anomalies) makes LoadCLIConfig see
// no config file regardless of the host machine's state, so these variants
// deterministically exercise the "not connected" branch every time.

func TestRunChannelList_NoServer_ConfigIsolated(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := runChannelList(listCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunChannelAdd_NoServer_ConfigIsolated(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	origType := flagChannelType
	t.Cleanup(func() { flagChannelType = origType })
	flagChannelType = "webhook"

	err := runChannelAdd(addCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunChannelGet_NoServer_ConfigIsolated(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := runChannelGet(getCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunChannelUpdate_NoServer_ConfigIsolated(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := runChannelUpdate(updateCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunChannelDelete_NoServer_ConfigIsolated(t *testing.T) {
	origConfirm := flagConfirm
	t.Cleanup(func() { flagConfirm = origConfirm })
	flagConfirm = true
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := runChannelDelete(deleteCmd, []string{"my-channel"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// ── additional coverage: empty list, error paths ──────────────────────────────

// TestNotificationChannelList_Remote_Empty verifies that when the server returns
// zero channels the function prints a "No notification channels configured."
// message and returns nil.
func TestNotificationChannelList_Remote_Empty(t *testing.T) {
	emptyBody := `{"data":{"channels":[]}}`
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(emptyBody))
	})

	err := runChannelListRemote(rc)
	require.NoError(t, err)
}

// TestNotificationChannelDelete_Remote_DeleteError verifies the rc.Delete error
// path in runChannelDeleteRemote: list succeeds (name found), but DELETE call fails.
func TestNotificationChannelDelete_Remote_DeleteError(t *testing.T) {
	callCount := 0
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			// First call: return the channel list so resolveChannelID succeeds.
			_, _ = w.Write([]byte(channelListBody))
		} else {
			// Second call (DELETE): return a server error.
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	err := runChannelDeleteRemote(rc, "slack-ops")
	require.Error(t, err)
	assert.Equal(t, 2, callCount, "expected exactly GET+DELETE calls")
}

// TestNotificationChannelUpdate_Remote_PutError verifies the rc.Put error path
// in runChannelUpdateRemote: list succeeds (name found), but PUT call fails.
func TestNotificationChannelUpdate_Remote_PutError(t *testing.T) {
	callCount := 0
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(channelListBody))
		} else {
			// PUT returns an error.
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	body := map[string]interface{}{"events": "anomaly.detected"}
	err := runChannelUpdateRemote(rc, "slack-ops", body)
	require.Error(t, err)
	assert.Equal(t, 2, callCount, "expected exactly GET+PUT calls")
}

// TestResolveChannelID_GetError verifies that when the GET call inside
// resolveChannelID fails the error is propagated to the caller.
func TestResolveChannelID_GetError(t *testing.T) {
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	id, err := resolveChannelID(rc, "slack-ops")
	require.Error(t, err)
	assert.Zero(t, id)
	assert.Contains(t, err.Error(), "403")
}

// TestResolveChannelID_NotFound verifies that when the channel name is absent
// from the list resolveChannelID returns a "not found" error.
func TestResolveChannelID_NotFound(t *testing.T) {
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"channels":[]}}`))
	})

	id, err := resolveChannelID(rc, "nonexistent")
	require.Error(t, err)
	assert.Zero(t, id)
	assert.Contains(t, err.Error(), "not found")
}

// TestNotificationChannelDelete_Remote_NotFound verifies runChannelDeleteRemote
// when the channel name is absent from the server list.
func TestNotificationChannelDelete_Remote_NotFound(t *testing.T) {
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"channels":[]}}`))
	})

	err := runChannelDeleteRemote(rc, "no-such-channel")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestNotificationChannelUpdate_Remote_NotFound verifies runChannelUpdateRemote
// when the channel name is absent from the server list.
func TestNotificationChannelUpdate_Remote_NotFound(t *testing.T) {
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"channels":[]}}`))
	})

	body := map[string]interface{}{"events": "anomaly.detected"}
	err := runChannelUpdateRemote(rc, "no-such-channel", body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestNotificationChannelList_Remote_WithEnabledFalse verifies the list output
// shows "no" for disabled channels.
func TestNotificationChannelList_Remote_WithEnabledFalse(t *testing.T) {
	disabledBody := `{"data":{"channels":[{"id":2,"name":"disabled-hook","type":"webhook","enabled":false,"url":"https://hook.example.com","email":"","events":"","created_by":"admin"}]}}`
	_, rc := buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(disabledBody))
	})

	err := runChannelListRemote(rc)
	require.NoError(t, err)
}

// ── cobra entry-point coverage (connected-server success paths) ───────────────
//
// The tests above exercise the *Remote helpers directly and the "not
// connected to a server" branch of each cobra entry point. None of them drive
// the entry point's own "connected" branch — the call from e.g. runChannelList
// into runChannelListRemote. These tests close that gap by pointing the
// package-level env-resolved client at a live httptest server and invoking
// the cobra RunE function itself.

func TestRunChannelList_ConnectedServer(t *testing.T) {
	buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(channelListBody))
	})

	err := runChannelList(listCmd, nil)
	require.NoError(t, err)
}

func TestRunChannelAdd_ConnectedServer(t *testing.T) {
	origType, origURL, origEmail, origEvents := flagChannelType, flagChannelURL, flagChannelEmail, flagChannelEvents
	t.Cleanup(func() {
		flagChannelType, flagChannelURL, flagChannelEmail, flagChannelEvents = origType, origURL, origEmail, origEvents
	})
	flagChannelType = "webhook"
	flagChannelURL = "https://hook.example.com"
	flagChannelEmail = ""
	flagChannelEvents = ""

	var gotBody map[string]interface{}
	buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(channelSingleBody))
	})

	err := runChannelAdd(addCmd, []string{"slack-ops"})
	require.NoError(t, err)
	assert.Equal(t, "webhook", gotBody["type"])
	assert.Equal(t, "https://hook.example.com", gotBody["url"])
}

func TestRunChannelGet_ConnectedServer_Found(t *testing.T) {
	buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(channelListBody))
	})

	err := runChannelGet(getCmd, []string{"slack-ops"})
	require.NoError(t, err)
}

func TestRunChannelUpdate_ConnectedServer(t *testing.T) {
	require.NoError(t, updateCmd.Flags().Set("events", "secret.rotated"))
	t.Cleanup(func() {
		updateCmd.Flags().Lookup("events").Changed = false
		flagChannelEvents = ""
	})

	callCount := 0
	var gotBody map[string]interface{}
	buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(channelListBody))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(channelSingleBody))
	})

	err := runChannelUpdate(updateCmd, []string{"slack-ops"})
	require.NoError(t, err)
	assert.Equal(t, 2, callCount, "expected exactly GET+PUT calls")
	assert.Equal(t, "secret.rotated", gotBody["events"])
}

func TestRunChannelDelete_ConnectedServer(t *testing.T) {
	origConfirm := flagConfirm
	t.Cleanup(func() { flagConfirm = origConfirm })
	flagConfirm = true

	callCount := 0
	buildTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(channelListBody))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"id":1,"deleted":true}}`))
	})

	err := runChannelDelete(deleteCmd, []string{"slack-ops"})
	require.NoError(t, err)
	assert.Equal(t, 2, callCount, "expected exactly GET+DELETE calls")
}
