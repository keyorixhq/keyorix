package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestSendActorGateError: a fault reading the acting account is a retry (503), a
// refusal is 403, and any other error is left to the route's own mapping.
func TestSendActorGateError(t *testing.T) {
	w := httptest.NewRecorder()
	assert.True(t, sendActorGateError(w, fmt.Errorf("resolving the acting account: %w", core.ErrStorageReadUnavailable)))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	w = httptest.NewRecorder()
	assert.True(t, sendActorGateError(w, fmt.Errorf("x: %w", core.ErrPermissionDenied)))
	assert.Equal(t, http.StatusForbidden, w.Code)

	w = httptest.NewRecorder()
	assert.False(t, sendActorGateError(w, fmt.Errorf("project ID and actor ID are required")))
	assert.Equal(t, http.StatusOK, w.Code, "nothing written")
}
