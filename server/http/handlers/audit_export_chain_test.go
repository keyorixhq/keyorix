package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestExportAuditLogs_CarriesChainLinks pins the ADR-029 off-box anchor: the SIEM-pull JSON
// export (GET /api/v1/audit/export) must carry each event's prev_hash AND entry_hash, so an
// off-box observer can reconstruct the tamper-evidence hash chain and detect on-box
// tampering — including tail-truncation, which on-box re-verification cannot catch. The
// handler includes these fields, but nothing guarded that they stay: a struct cleanup that
// dropped them would silently void the documented anchor with no other test failing. (The
// async SIEM push forwarder deliberately omits them — it is a best-effort, lossy stream and
// cannot anchor a chain; the pull export is the authoritative, ordered channel.)
func TestExportAuditLogs_CarriesChainLinks(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))

	ls := store.NewLocalStorage(db)
	ctx := context.Background()
	tru := true
	// Seed a real chain via LogAuditEvent so prev_hash/entry_hash are computed and linked.
	for i, desc := range []string{"first", "second", "third"} {
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "secret.read", Description: desc, Success: &tru,
			EventTime: time.Now().Add(time.Duration(i) * time.Second), ActorType: "user",
		}))
	}

	h := NewAuditHandler(core.NewKeyorixCore(ls))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data struct {
			Events []struct {
				ID        uint   `json:"id"`
				PrevHash  string `json:"prev_hash"`
				EntryHash string `json:"entry_hash"`
			} `json:"events"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data.Events, 3)

	// Every exported event must carry both chain links — the anchor is useless without them.
	for i, e := range resp.Data.Events {
		assert.NotEmpty(t, e.EntryHash, "event %d must export its entry_hash", i)
		assert.NotEmpty(t, e.PrevHash, "event %d must export its prev_hash", i)
	}
	// And the links must actually chain (export is ascending by id): each event's prev_hash
	// equals the previous event's entry_hash, so the off-box observer can verify end-to-end.
	assert.Equal(t, resp.Data.Events[0].EntryHash, resp.Data.Events[1].PrevHash,
		"event 2's prev_hash must link to event 1's entry_hash")
	assert.Equal(t, resp.Data.Events[1].EntryHash, resp.Data.Events[2].PrevHash,
		"event 3's prev_hash must link to event 2's entry_hash")
}
