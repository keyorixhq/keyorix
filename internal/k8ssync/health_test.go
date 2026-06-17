package k8ssync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHealth_LivenessAlwaysOK(t *testing.T) {
	h := NewStatus().Handler()
	rec := get(t, h, "/healthz")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHealth_ReadinessGatesOnFirstSync(t *testing.T) {
	s := NewStatus()
	h := s.Handler()

	// Before any reconcile: not ready.
	assert.Equal(t, http.StatusServiceUnavailable, get(t, h, "/readyz").Code)

	// After a pass completes: ready.
	s.Record(Result{Created: 2})
	assert.Equal(t, http.StatusOK, get(t, h, "/readyz").Code)
}

func TestHealth_StatusReportsCounts(t *testing.T) {
	s := NewStatus()
	h := s.Handler()

	// Before a run.
	var before map[string]interface{}
	require.NoError(t, json.Unmarshal(get(t, h, "/status").Body.Bytes(), &before))
	assert.Equal(t, false, before["ran"])
	_, hasLastRun := before["last_run"]
	assert.False(t, hasLastRun, "no last_run before the first pass")

	// After a run with mixed outcomes.
	s.Record(Result{Created: 1, Updated: 2, Unchanged: 3, Failed: 1, Errors: []string{"app/x: boom"}})
	var after map[string]interface{}
	require.NoError(t, json.Unmarshal(get(t, h, "/status").Body.Bytes(), &after))
	assert.Equal(t, true, after["ran"])
	assert.EqualValues(t, 1, after["created"])
	assert.EqualValues(t, 2, after["updated"])
	assert.EqualValues(t, 3, after["unchanged"])
	assert.EqualValues(t, 1, after["failed"])
	assert.EqualValues(t, 1, after["errors"], "error count, not the messages")
	assert.Contains(t, after, "last_run")
}
