package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorage_404_SurfacesStructuredError proves the fix for #501: a
// genuine 404 from a REAL production handler (server/http/handlers.GetUser,
// via sendError) must surface the server's actual structured error type and
// message through store.RemoteStorage/internal/storage/remote.HTTPClient,
// instead of the old generic "HTTP 404: 404 Not Found" string that discarded
// the parsed JSON error envelope on every 4xx/5xx response.
//
// This talks to an ACTUAL httptest-backed NewRouter(...) instance (the same
// pattern as TestRemoteStorage_SuccessFieldFix_RealServerRoundTrip, #794) —
// not a hand-rolled mock server standing in for the wire shape — so it also
// pins the real wire format sendError emits (a flat {"error":"<type
// string>","message":...} object, not the nested {"error":{"code":...}}
// shape internal/storage/remote.APIError models).
func TestRemoteStorage_404_SurfacesStructuredError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)

	// A user ID that genuinely does not exist on the real upstream — this hits
	// handlers.GetUser -> sendError(w, "NotFound", "User not found", 404, nil).
	const nonExistentUserID = 999999
	_, err = rs.GetUser(context.Background(), nonExistentUserID)
	require.Error(t, err)

	var httpErr *remote.HTTPError
	require.True(t, errors.As(err, &httpErr),
		"GetUser's error must unwrap to *remote.HTTPError so callers can type-assert instead of string-matching; got: %v", err)

	assert.Equal(t, 404, httpErr.StatusCode)
	assert.True(t, httpErr.IsNotFound())
	assert.Equal(t, "NotFound", httpErr.ErrorType,
		"the real handler's structured error type ('NotFound') must survive, not be discarded")
	assert.Equal(t, "User not found", httpErr.Message,
		"the real handler's structured error message must survive, not be replaced with a generic HTTP status string")

	// The old, pre-fix failure mode: the ONLY information reaching the caller
	// was a generic status-line string. Confirm that's no longer all we get —
	// the real message must appear in Error() text too.
	assert.Contains(t, err.Error(), "User not found")
	assert.NotEqual(t, "HTTP 404: 404 Not Found", err.Error(),
		"the structured server error must not collapse into the old generic HTTP-status-only string")
}
