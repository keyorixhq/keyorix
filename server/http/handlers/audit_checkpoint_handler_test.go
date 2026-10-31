package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With encryption disabled the core holds no KEK-derived signing key, so an
// on-demand checkpoint write is a precondition failure (412), not a 500.
func TestAuditHandler_WriteCheckpoint_RequiresEncryption(t *testing.T) {
	db := openTestDB(t)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil))
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)

	assert.Equal(t, http.StatusPreconditionFailed, w.Code)
}

// The checkpoint signing key is KEK-derived, so the 412 text must say KEK.
func TestAuditHandler_WriteCheckpoint_RequiresEncryption_NamesKEK(t *testing.T) {
	db := openTestDB(t)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil))
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)

	require.Equal(t, http.StatusPreconditionFailed, w.Code)
	assert.Contains(t, w.Body.String(), "the signing key is derived from the KEK")
	assert.NotContains(t, w.Body.String(), "DEK")
}

func TestAuditHandler_WriteCheckpoint_RequiresUserContext(t *testing.T) {
	db := openTestDB(t)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil)
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
