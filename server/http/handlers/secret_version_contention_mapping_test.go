// secret_version_contention_mapping_test.go — W3 (Session W, 2026-09-29): pins
// the HTTP-layer half of the fix — ErrSecretVersionContentionExhausted (thrown
// when updateSecretWithNewVersion/storeNextSecretVersion exhaust their retry
// budget under sustained concurrent writes to one secret) must map to 409
// Conflict with a retry hint, not the generic 500 every other unrecognized
// error falls through to.
package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendUpdateSecretError_VersionContentionExhausted_Maps409NotGeneric500(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	h := &SecretHandler{}
	w := httptest.NewRecorder()

	wrapped := fmt.Errorf("Storage operation failed: %w", core.ErrSecretVersionContentionExhausted)
	h.sendUpdateSecretError(w, wrapped)

	assert.Equal(t, http.StatusConflict, w.Code, "contention exhaustion must be 409, not a generic 500: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "retry", "the response should hint that retrying is the right move")
}

// TestSendUpdateSecretError_GenericError_StillMaps500 is the negative control:
// an ordinary, unrecognized storage error must still fall through to the
// existing generic 500 — this fix must not swallow every InternalError into
// a 409.
func TestSendUpdateSecretError_GenericError_StillMaps500(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	h := &SecretHandler{}
	w := httptest.NewRecorder()

	h.sendUpdateSecretError(w, errors.New("some unrelated storage failure"))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
