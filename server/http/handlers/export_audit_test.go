package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// export_audit_test.go — AUDIT-FAILCLOSED-SECRETS-1 (#4721): a bulk export of
// security-relevant data is recorded before it is delivered, fail-closed. Red on
// main: GET /compliance/evidence and GET /audit/export.csv wrote no row at all, so
// the success legs find none and the outage legs get a 200 with the data.

type exportFixture struct {
	db      *gorm.DB
	core    *core.KeyorixCore
	refused atomic.Value // event type whose append fails ("" = none)
}

func newExportFixture(t *testing.T) *exportFixture {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open("file:"+filepath.Join(t.TempDir(), "export.db")+"?_busy_timeout=5000"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, kxstorage.MigrateExisting(db))
	f := &exportFixture{db: db}
	f.refused.Store("")
	f.core = core.NewKeyorixCore(storagetest.Hooked(store.NewLocalStorage(db), &storagetest.StoreHooks{
		WrapTx: true,
		LogAuditEvent: func(next coreStorage.Storage, ctx context.Context, e *models.AuditEvent) error {
			if e.EventType == f.refused.Load().(string) {
				return fmt.Errorf("fault-injected: %s audit write failed", e.EventType)
			}
			return next.LogAuditEvent(ctx, e)
		},
	}))
	// Something to export.
	require.NoError(t, db.Create(&models.AuditEvent{EventType: "secret.created", Description: "seed row"}).Error)
	return f
}

func (f *exportFixture) rows(t *testing.T, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

func (f *exportFixture) all(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&models.AuditEvent{}).Count(&n).Error)
	return n
}

func TestExportAuditLogsCSV_RecordedBeforeDelivery(t *testing.T) {
	f := newExportFixture(t)
	h := NewAuditHandler(f.core)

	w := httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv?limit=50", nil)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "seed row")
	assert.NotContains(t, w.Body.String(), "audit.exported", "the export is the trail as it stood: not its own row")
	assert.EqualValues(t, 1, f.rows(t, "audit.exported"), "the CSV export must be on record")

	f.refused.Store("audit.exported")
	w = httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv?limit=50", nil)))
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.Empty(t, w.Header().Get("Content-Disposition"), "a refused export sends no file")
	assert.Contains(t, w.Body.String(), auditUnavailableCode)
	assert.NotContains(t, w.Body.String(), "seed row", "a refused export discloses no audit row")
	assert.EqualValues(t, 1, f.rows(t, "audit.exported"))
}

func TestGetComplianceEvidence_RecordedBeforeDelivery(t *testing.T) {
	f := newExportFixture(t)
	h := NewDashboardHandler(f.core)

	w := httptest.NewRecorder()
	h.GetComplianceEvidence(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence", nil)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "data_b64")
	assert.EqualValues(t, 1, f.rows(t, "compliance.evidence_exported"), "the evidence download must be on record")

	f.refused.Store("compliance.evidence_exported")
	w = httptest.NewRecorder()
	h.GetComplianceEvidence(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence", nil)))
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.Contains(t, w.Body.String(), auditUnavailableCode)
	assert.NotContains(t, w.Body.String(), "data_b64", "a refused export sends no pack")
	assert.NotContains(t, w.Body.String(), "signature")
}

// TestAuditExportFeed_WritesNoAuditRowOfItsOwn pins the one export left unaudited on
// purpose (#4721, ADR-112 note): the JSON SIEM pull feed. A collector polls it by
// cursor; a row per poll would be returned by the next poll, so the feed would never
// be caught up and the trail would grow by one row per poll forever.
func TestAuditExportFeed_WritesNoAuditRowOfItsOwn(t *testing.T) {
	f := newExportFixture(t)
	h := NewAuditHandler(f.core)
	before := f.all(t)
	for range 3 {
		w := httptest.NewRecorder()
		h.ExportAuditLogs(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?limit=10", nil)))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	assert.Equal(t, before, f.all(t), "a SIEM pull of the audit feed must not append to the feed it reads")
}
