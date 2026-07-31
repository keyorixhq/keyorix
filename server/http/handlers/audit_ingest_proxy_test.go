package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var auditIngestTestCounter atomic.Int64

func newAuditIngestHandler(t *testing.T) *AuditHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := auditIngestTestCounter.Add(1)
	dsn := fmt.Sprintf("file:kxauditingest_%d?mode=memory&cache=shared&_busy_timeout=5000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
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

// TestIngestAuditEventProxy_StorageError verifies that a storage failure (e.g.
// missing table) is surfaced as a 500 response, not a silent no-op.
func TestIngestAuditEventProxy_StorageError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	// Open a DB with NO tables — LogAuditEvent will fail with "no such table".
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	body, _ := json.Marshal(map[string]any{"event_type": "secret.read"})
	w := postAuditIngest(h.IngestAuditEventProxy, body)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestIngestAuditEventProxy_IDZeroedOnArrival pins r123: a caller-supplied ID
// must not be forwarded to the hub DB — the hub assigns its own auto-increment
// ID so that chain positions cannot be forged and VerifyAuditChain stays intact.
func TestIngestAuditEventProxy_IDZeroedOnArrival(t *testing.T) {
	h := newAuditIngestHandler(t)
	// Supply a large ID that would land far into the auto-increment sequence.
	body, _ := json.Marshal(map[string]any{
		"id":          9999,
		"event_type":  "secret.read",
		"description": "follower event with caller-supplied ID",
	})
	w := postAuditIngest(h.IngestAuditEventProxy, body)
	require.Equal(t, http.StatusOK, w.Code)

	// The persisted row must have received a DB-assigned ID, not 9999.
	// The first row in a fresh DB gets ID 1.
	// Query the event directly via GORM through the same DB would require
	// exposing internals; instead verify the response reports success and
	// a second insert does not fail with a duplicate-key error (which would
	// happen if two events both tried to claim ID 9999).
	body2, _ := json.Marshal(map[string]any{
		"id":          9999,
		"event_type":  "secret.write",
		"description": "second event, same forged ID",
	})
	w2 := postAuditIngest(h.IngestAuditEventProxy, body2)
	assert.Equal(t, http.StatusOK, w2.Code, "second event with same caller ID must succeed because IDs are zeroed")
}
