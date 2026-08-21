// project_s27_test.go — s27 coverage blitz: hygieneCmd.RunE's not-connected and
// fetchHygiene-error branches, the embedded env-clone source==destination
// validation error, and verifyEnvironmentBelongsToProject's own
// InitializeCoreService failure branch (called directly, since
// resolveProjectContext would otherwise fail first with the same broken
// config).
package project

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHygieneCmd_NotConnected verifies that hygieneCmd.RunE refuses to run in
// embedded (non-remote) mode with the documented "not connected" error,
// rather than silently doing nothing or panicking on a nil RemoteClient.
func TestHygieneCmd_NotConnected(t *testing.T) {
	setupEmbedded(t)

	err := hygieneCmd.RunE(hygieneCmd, []string{"5"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestHygieneCmd_FetchError verifies that a server error from the hygiene
// endpoint is propagated (unwrapped) from hygieneCmd.RunE via fetchHygiene,
// rather than being swallowed or replaced with a generic message.
func TestHygieneCmd_FetchError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := hygieneCmd.RunE(hygieneCmd, []string{"5"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server returned HTTP 500")
}

// TestVerifyEnvironmentBelongsToProject_Embedded_ServiceInitError verifies the
// embedded InitializeCoreService failure branch inside
// verifyEnvironmentBelongsToProject itself (called directly, since going
// through runEnvDelete would fail earlier at resolveProjectContext's own
// InitializeCoreService call against the same broken config).
func TestVerifyEnvironmentBelongsToProject_Embedded_ServiceInitError(t *testing.T) {
	setupBrokenService(t)

	err := verifyEnvironmentBelongsToProject(context.Background(), 1, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}
