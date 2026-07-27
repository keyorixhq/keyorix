package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newAuditIngestHandler(t *testing.T) *AuditHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open("file::memory:?mode=memory&cache=shared&_busy_timeout=5000"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	return NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

func postAuditIngest(h http.HandlerFunc, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/audit/event", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// TestIngestAuditEventProxy_HappyPath verifies that a valid AuditEvent is
// persisted and returns 200.
func TestIngestAuditEventProxy_HappyPath(t *testing.T) {
	h := newAuditIngestHandler(t)
	body, _ := json.Marshal(map[string]any{
		"event_type":  "secret.read",
		"description": "remote follower event",
	})
	w := postAuditIngest(h.IngestAuditEventProxy, body)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["success"])
}

// TestIngestAuditEventProxy_InvalidJSON verifies that malformed JSON returns 400.
func TestIngestAuditEventProxy_InvalidJSON(t *testing.T) {
	h := newAuditIngestHandler(t)
	w := postAuditIngest(h.IngestAuditEventProxy, []byte("not-json{{{"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
