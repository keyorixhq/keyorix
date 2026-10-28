package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// REVFIX-3751-1: a blank or whitespace-only user is the caller's mistake, a 400
// ValidationError, never a 500.
func TestContractMFAReset_BlankUserIsValidationError(t *testing.T) {
	w := newMFAResetHandlerWorld(t)
	old := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = old })
	uh, err := NewUserHandler(w.cs)
	require.NoError(t, err)
	defaultUserHandler = uh

	for _, ref := range []string{"", "   "} {
		rec := w.call(t, w.a, RequestMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests", "",
			fmt.Sprintf(`{"user":%q,"reason":"lost phone","verified_by":"video","code":"123456"}`, ref))
		require.Equal(t, http.StatusBadRequest, rec.Code, "user %q: %s", ref, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "ValidationError", "user %q", ref)
	}
}
