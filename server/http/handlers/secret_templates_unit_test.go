// secret_templates_unit_test.go — unit tests for SecretTemplateHandler that
// exercise branches unreachable through the HTTP router (e.g. nil-user context).
package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretTemplateCreate_NilUser exercises the nil-user-context guard in
// Create. In production this path is unreachable (RequirePermission middleware
// returns 401 first), but the guard is a defensive in-handler check that
// requires its own test for complete line coverage.
func TestSecretTemplateCreate_NilUser(t *testing.T) {
	// Create the handler with a nil coreService — the nil-user check fires
	// before coreService is ever called, so no panic.
	h := NewSecretTemplateHandler(nil)

	body := bytes.NewBufferString(`{"name":"tpl"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	// Deliberately omit any user in the context — middleware.GetUserFromContext
	// will return nil.

	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
