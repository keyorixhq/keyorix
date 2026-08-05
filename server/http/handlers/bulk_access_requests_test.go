// bulk_access_requests_test.go — unit tests for bulk approve/reject and
// rejection-reason-template endpoints on CatalogHandler.
package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

var bulkHandlerCounter int

func newBulkAccessTestHandler(t *testing.T) *CatalogHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	bulkHandlerCounter++
	dsn := fmt.Sprintf("file:bah%d?mode=memory&cache=private", bulkHandlerCounter)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AccessRequest{},
		&models.RejectionReasonTemplate{},
	))
	t.Cleanup(func() { sqlDB, _ := db.DB(); _ = sqlDB.Close() })
	return NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

// newBulkAccessBrokenHandler returns a CatalogHandler backed by a closed
// SQLite connection so that every storage call returns a DB error, allowing
// coverage of the 500 error-path branches in each handler function.
func newBulkAccessBrokenHandler(t *testing.T) *CatalogHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	bulkHandlerCounter++
	dsn := fmt.Sprintf("file:bah_broken%d?mode=memory&cache=shared", bulkHandlerCounter)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AccessRequest{},
		&models.RejectionReasonTemplate{},
	))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

// ── BulkApproveAccessRequests ─────────────────────────────────────────────────

func TestBulkApprove_NilUser(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"request_ids":[1]}`))
	w := httptest.NewRecorder()
	h.BulkApproveAccessRequests(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBulkApprove_InvalidJSON(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.BulkApproveAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBulkApprove_EmptyIDs(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"request_ids":[]}`)))
	w := httptest.NewRecorder()
	h.BulkApproveAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBulkApprove_TooManyIDs(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	// One over core.maxBulkAccessRequestBatchSize (500) — the cap is unexported,
	// so this mirrors that value rather than importing it.
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = fmt.Sprintf("%d", i+1)
	}
	body := fmt.Sprintf(`{"request_ids":[%s]}`, strings.Join(ids, ","))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)))
	w := httptest.NewRecorder()
	h.BulkApproveAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "maximum batch size")
}

func TestBulkApprove_NotFound_ReturnsSuccess(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"request_ids":[9999]}`)))
	w := httptest.NewRecorder()
	h.BulkApproveAccessRequests(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "result")
}

// ── BulkRejectAccessRequests ──────────────────────────────────────────────────

func TestBulkReject_NilUser(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"request_ids":[1]}`))
	w := httptest.NewRecorder()
	h.BulkRejectAccessRequests(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBulkReject_InvalidJSON(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.BulkRejectAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBulkReject_EmptyIDs(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"request_ids":[],"reason":"too risky"}`)))
	w := httptest.NewRecorder()
	h.BulkRejectAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBulkReject_TooManyIDs(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	// One over core.maxBulkAccessRequestBatchSize (500) — the cap is unexported,
	// so this mirrors that value rather than importing it.
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = fmt.Sprintf("%d", i+1)
	}
	body := fmt.Sprintf(`{"request_ids":[%s],"reason":"too risky"}`, strings.Join(ids, ","))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)))
	w := httptest.NewRecorder()
	h.BulkRejectAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "maximum batch size")
}

func TestBulkReject_NotFound_ReturnsSuccess(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"request_ids":[9999],"reason":"expired"}`)))
	w := httptest.NewRecorder()
	h.BulkRejectAccessRequests(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "result")
}

// ── CreateRejectionReasonTemplate ─────────────────────────────────────────────

func TestCreateRejectionTemplate_NilUser(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"x","reason":"y"}`))
	w := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateRejectionTemplate_InvalidJSON(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateRejectionTemplate_NameRequired(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"","reason":"y"}`)))
	w := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateRejectionTemplate_Success(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"inactive","reason":"Account inactive"}`)))
	w := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "inactive")
}

// ── ListRejectionReasonTemplates ──────────────────────────────────────────────

func TestListRejectionTemplates_Empty(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRejectionReasonTemplates(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "templates")
}

func TestListRejectionTemplates_WithData(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	cw := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		bytes.NewBufferString(`{"name":"t1","reason":"reason one"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRejectionReasonTemplates(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "t1")
}

// ── DeleteRejectionReasonTemplate ─────────────────────────────────────────────

func TestDeleteRejectionTemplate_InvalidID(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "abc")
	w := httptest.NewRecorder()
	h.DeleteRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteRejectionTemplate_NotFound(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.DeleteRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteRejectionTemplate_Success(t *testing.T) {
	h := newBulkAccessTestHandler(t)
	cw := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		bytes.NewBufferString(`{"name":"del-me","reason":"to delete"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── 500 error-path coverage (broken DB) ──────────────────────────────────────

func TestBulkApprove_DBError_Returns500(t *testing.T) {
	h := newBulkAccessBrokenHandler(t)
	// DB is closed: ListAccessRequestsByIDs returns a generic error (not "required")
	// which routes to the 500 branch in BulkApproveAccessRequests.
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		bytes.NewBufferString(`{"request_ids":[1]}`)))
	w := httptest.NewRecorder()
	h.BulkApproveAccessRequests(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBulkReject_DBError_Returns500(t *testing.T) {
	h := newBulkAccessBrokenHandler(t)
	// DB is closed: ListAccessRequestsByIDs returns a generic error (not "required")
	// which routes to the 500 branch in BulkRejectAccessRequests.
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		bytes.NewBufferString(`{"request_ids":[1],"reason":"expired"}`)))
	w := httptest.NewRecorder()
	h.BulkRejectAccessRequests(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateRejectionTemplate_DBError_Returns500(t *testing.T) {
	h := newBulkAccessBrokenHandler(t)
	// DB is closed: CreateRejectionReasonTemplate returns a generic error (not
	// "required") which routes to the 500 else-branch.
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		bytes.NewBufferString(`{"name":"x","reason":"y"}`)))
	w := httptest.NewRecorder()
	h.CreateRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListRejectionTemplates_DBError_Returns500(t *testing.T) {
	h := newBulkAccessBrokenHandler(t)
	// DB is closed: ListRejectionReasonTemplates returns an error that triggers
	// the 500 branch.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRejectionReasonTemplates(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteRejectionTemplate_DBError_Returns500(t *testing.T) {
	h := newBulkAccessBrokenHandler(t)
	// DB is closed: DeleteRejectionReasonTemplate returns a generic error (not
	// "not found") which routes to the 500 else-branch.
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRejectionReasonTemplate(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
