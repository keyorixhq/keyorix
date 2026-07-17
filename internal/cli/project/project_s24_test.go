// project_s24_test.go — additional coverage for hygiene RunE paths.
package project

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHygieneCmd_InvalidID verifies that a non-numeric project ID argument
// is rejected with an "invalid project ID" error before any network call.
func TestHygieneCmd_InvalidID(t *testing.T) {
	setupEmbedded(t)
	err := hygieneCmd.RunE(hygieneCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid project ID")
}

// TestHygieneCmd_RemoteSuccess verifies that hygieneCmd.RunE fetches and prints
// the hygiene summary when a valid project ID is given and the server responds.
func TestHygieneCmd_RemoteSuccess(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/5/hygiene" {
			_, _ = w.Write([]byte(`{"data":{"orphaned_secrets":2,"unused_secrets":1,"expiring_secrets":0,"stale_machine_identities":3,"rotation_overdue":0}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	out := captureStdout(t, func() {
		require.NoError(t, hygieneCmd.RunE(hygieneCmd, []string{"5"}))
	})
	assert.Contains(t, out, "Hygiene for project 5:")
	assert.Contains(t, out, "orphaned secrets")
	assert.Contains(t, out, "2")
	assert.Contains(t, out, "stale machine identities")
	assert.Contains(t, out, "3")
}
