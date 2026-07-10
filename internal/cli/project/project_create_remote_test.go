package project

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunCreate_Remote verifies project create POSTs to /api/v1/projects and prints
// the created project details in remote mode.
func TestRunCreate_Remote(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]interface{}

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		// Respond with the real server envelope shape.
		_, _ = w.Write([]byte(`{"success":true,"data":{"id":42,"name":"myapp","description":""}}`))
	})

	createName = "myapp"
	createDescription = ""
	createEnvs = ""

	out := captureStdout(t, func() { require.NoError(t, runCreate(nil, nil)) })

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/projects", gotPath)
	assert.Equal(t, "myapp", gotBody["name"])
	assert.Contains(t, out, "Project created: id=42")
	assert.Contains(t, out, "Default environments")
}

// TestRunCreate_Remote_WithEnvs verifies that --envs is sent as "environments" to the server.
func TestRunCreate_Remote_WithEnvs(t *testing.T) {
	var gotBody map[string]interface{}

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"success":true,"data":{"id":5,"name":"api","description":""}}`))
	})

	createName = "api"
	createDescription = "the api"
	createEnvs = "dev,prod"

	out := captureStdout(t, func() { require.NoError(t, runCreate(nil, nil)) })

	// The server field must be "environments" (not "envs") so the server seeds the envs.
	require.Contains(t, gotBody, "environments", "the JSON key must be 'environments' not 'envs'")
	assert.Contains(t, out, "Environments seeded: dev,prod")
}

// TestRunCreate_Remote_ServerError verifies the error is surfaced.
func TestRunCreate_Remote_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	createName = "fail"

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestRunList_Remote_ServerError verifies errors from /api/v1/projects are surfaced.
func TestRunList_Remote_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}
