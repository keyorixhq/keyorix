package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// openAuditChainTestDB opens a fresh in-memory SQLite DB migrated for the
// audit hash-chain tables only — this handler's underlying core/storage call
// touches audit_events and system_metadata (for the retention anchor), not
// the RBAC tables openTestDB sets up for other handlers.
func openAuditChainTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SystemMetadata{}))
	return db
}

func TestAuditHandler_MigrateChainEncoding_RequiresUserContext(t *testing.T) {
	db := openAuditChainTestDB(t)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/migrate-chain-encoding", nil)
	w := httptest.NewRecorder()
	h.MigrateAuditChainEncoding(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// No query string at all must behave identically to the safe default
// (dry_run=true) — an operator who omits the parameter, or mistypes it,
// still only gets a preview.
func TestAuditHandler_MigrateChainEncoding_DefaultsToDryRun(t *testing.T) {
	db := openAuditChainTestDB(t)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/migrate-chain-encoding", nil))
	w := httptest.NewRecorder()
	h.MigrateAuditChainEncoding(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Data struct {
			DryRun bool `json:"dry_run"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.True(t, body.Data.DryRun, "no dry_run query param must default to a preview, never a real run")
}

// A typo'd or unrecognized dry_run value must still fail SAFE (preview), not
// accidentally opt into a real run — only the literal string "false" does.
func TestAuditHandler_MigrateChainEncoding_UnrecognizedDryRunValueStaysDryRun(t *testing.T) {
	db := openAuditChainTestDB(t)
	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/migrate-chain-encoding?dry_run=nope", nil))
	w := httptest.NewRecorder()
	h.MigrateAuditChainEncoding(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Data struct {
			DryRun bool `json:"dry_run"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.True(t, body.Data.DryRun)
}

func TestAuditHandler_MigrateChainEncoding_ExplicitFalseAppliesForReal(t *testing.T) {
	db := openAuditChainTestDB(t)
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	h := NewAuditHandler(c)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/migrate-chain-encoding?dry_run=false", nil))
	w := httptest.NewRecorder()
	h.MigrateAuditChainEncoding(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Data struct {
			DryRun               bool   `json:"dry_run"`
			RowsMigrated         int64  `json:"rows_migrated"`
			UnchainedRowsSkipped int64  `json:"unchained_rows_skipped"`
			HeadID               uint   `json:"head_id"`
			HeadHash             string `json:"head_hash"`
		} `json:"data"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.False(t, body.Data.DryRun)
	assert.Contains(t, body.Message, "applied")
}
