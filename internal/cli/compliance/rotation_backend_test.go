package compliance

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const backendPayloadFull = `{"success":true,"data":{
	"generated_at":"2026-07-20T12:00:00Z",
	"total_overdue":3,
	"backends":[
		{"backend":"vault","total":10,"overdue":2,"up_to_date":7,"never_rotated":1},
		{"backend":"","total":5,"overdue":1,"up_to_date":3,"never_rotated":1}
	]
}}`

const backendPayloadEmpty = `{"success":true,"data":{
	"generated_at":"2026-07-20T12:00:00Z",
	"total_overdue":0,
	"backends":[]
}}`

func TestRotationByBackend_NotConnected(t *testing.T) {
	setupDisconnected(t)
	err := rotationByBackendCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRotationByBackend_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"internal error"}`))
	})
	err := rotationByBackendCmd.RunE(nil, nil)
	require.Error(t, err)
}

func TestRotationByBackend_WithBackends(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/rotation-by-backend", r.URL.Path)
		_, _ = w.Write([]byte(backendPayloadFull))
	})

	out := captureStdout(t, func() { require.NoError(t, rotationByBackendCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Total overdue: 3")
	assert.Contains(t, out, "vault")
	assert.Contains(t, out, "(keyorix-internal)")
	assert.Contains(t, out, "BACKEND")
	assert.Contains(t, out, "OVERDUE")
}

func TestRotationByBackend_EmptyBackends(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/rotation-by-backend", r.URL.Path)
		_, _ = w.Write([]byte(backendPayloadEmpty))
	})

	out := captureStdout(t, func() { require.NoError(t, rotationByBackendCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "No rotation policies found.")
	assert.Contains(t, out, "Total overdue: 0")
}
