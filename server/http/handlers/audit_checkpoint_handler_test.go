package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
)

// With encryption disabled the core holds no DEK-derived signing key, so an
// on-demand checkpoint write is a precondition failure (412), not a 500.
func TestAuditHandler_WriteCheckpoint_RequiresEncryption(t *testing.T) {
	db := openTestDB(t)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil))
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)

	assert.Equal(t, http.StatusPreconditionFailed, w.Code)
}

func TestAuditHandler_WriteCheckpoint_RequiresUserContext(t *testing.T) {
	db := openTestDB(t)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil)
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
