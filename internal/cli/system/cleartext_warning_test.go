// cleartext_warning_test.go — #G74: remote bootstrap ('system init --server')
// POSTs the admin username/email/password and bootstrap token to the
// user-supplied --server URL with no cleartext-transmission warning when that
// URL isn't HTTPS. Verifies the warning fires before the request completes
// for a plaintext http:// server, and stays silent for https://.
//
// The stub server is deliberately bound to 0.0.0.0 rather than the httptest
// default of 127.0.0.1: common.WarnIfInsecureEndpoint treats any loopback
// target as an allowed local-testing exception, so a plain httptest.Server
// URL would never exercise the "real" non-HTTPS warning path. Connecting to
// 0.0.0.0 as a destination is handled by the OS as connecting to localhost,
// so the server stays reachable from this process while its URL is
// classified as non-loopback.
package system

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nonLoopbackBootstrapStub(t *testing.T, tlsMode bool) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"already_initialized":true}}`))
	})
	ts := httptest.NewUnstartedServer(handler)
	require.NoError(t, ts.Listener.Close())
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	ts.Listener = ln
	if tlsMode {
		ts.StartTLS()
	} else {
		ts.Start()
	}
	t.Cleanup(ts.Close)
	return ts
}

func TestRunInit_WarnsOnPlaintextHTTPServer(t *testing.T) {
	resetInitFlags(t)
	srv := nonLoopbackBootstrapStub(t, false)
	require.NoError(t, InitCmd.Flags().Set("server", srv.URL))
	require.NoError(t, InitCmd.Flags().Set("admin-password", "correct-horse-battery-staple"))

	out := captureStderr(t, func() {
		require.NoError(t, runInit(InitCmd, nil))
	})
	assert.Contains(t, out, "not HTTPS")
	assert.Contains(t, out, "cleartext")
	assert.Contains(t, out, "MITM-capturable")
}

func TestRunInit_NoWarningOnHTTPSServer(t *testing.T) {
	resetInitFlags(t)
	srv := nonLoopbackBootstrapStub(t, true)
	require.NoError(t, InitCmd.Flags().Set("server", srv.URL))
	require.NoError(t, InitCmd.Flags().Set("admin-password", "correct-horse-battery-staple"))

	out := captureStderr(t, func() {
		// The self-signed cert has no SAN for 0.0.0.0, so the TLS handshake
		// may fail — irrelevant here, only the absence of the scheme warning
		// (printed before the request is ever attempted) is under test.
		_ = runInit(InitCmd, nil)
	})
	assert.NotContains(t, out, "not HTTPS")
	assert.NotContains(t, out, "MITM-capturable")
}
