// handlers_s34_test.go — broken-DB error-path sweep for regular (non-proxy)
// handler functions whose storage-error branch was not yet covered: catalog,
// break-glass, access-review, audit, and dashboard.
package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

var s34DBCounter atomic.Int64

func freshCoreBrokenS34(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s34DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s34_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// ── CatalogHandler / access_review_campaigns.go ───────────────────────────────

func TestListAccessReviewCampaigns_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/access-review/campaigns", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / break_glass.go ───────────────────────────────────────────

func TestListBreakGlassActivations_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/break-glass", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / catalog.go ───────────────────────────────────────────────

func TestGetProjectDrift_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/drift", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectDrift(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectEnvironments_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/environments", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectEnvironments_IncludeDeleted_DBError_S34(t *testing.T) {
	// Exercises the include_deleted=true branch of ListProjectEnvironments.
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS34(t))
	r := withChiParamS7(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/environments?include_deleted=true", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuditHandler / audit.go ───────────────────────────────────────────────────

func TestGetAuditRetention_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewAuditHandler(freshCoreBrokenS34(t))
	r := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil))
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestVerifyAuditChain_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewAuditHandler(freshCoreBrokenS34(t))
	r := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil))
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestWriteAuditCheckpoint_DBError_S34(t *testing.T) {
	t.Parallel()
	h := NewAuditHandler(freshCoreBrokenS34(t))
	r := withUserCtxS7(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil))
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, r)
	// With no encryption configured, WriteAuditCheckpoint returns (nil, false, nil) →
	// the !written branch fires → 412 PreconditionFailed.
	assert.Equal(t, http.StatusPreconditionFailed, w.Code)
}
