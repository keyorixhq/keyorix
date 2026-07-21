// secret_templates_handler_test.go — unit tests for SecretTemplateHandler.
// These tests run inside package handlers so they count toward handler coverage.
package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

var stHandlerCounter int

func newSecretTemplateTestHandler(t *testing.T) *SecretTemplateHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	stHandlerCounter++
	dsn := fmt.Sprintf("file:sth%d?mode=memory&cache=private", stHandlerCounter)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretTemplate{}))
	t.Cleanup(func() { sqlDB, _ := db.DB(); _ = sqlDB.Close() })
	return NewSecretTemplateHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

func stChiID(r *http.Request, id string) *http.Request {
	return withChiParam(r, "id", id)
}

// ── Create ────────────────────────────────────────────────────────────────────

func TestSecretTemplateHandler_Create_Success(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	body := bytes.NewBufferString(`{"name":"db-creds","description":"DB","default_classification":"internal"}`)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", body))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "db-creds")
}

func TestSecretTemplateHandler_Create_InvalidJSON(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Create_NameRequired(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	body := bytes.NewBufferString(`{"name":""}`)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", body))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Create_InvalidClassification(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	body := bytes.NewBufferString(`{"name":"t1","default_classification":"ULTRA_SECRET"}`)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", body))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── List ──────────────────────────────────────────────────────────────────────

func TestSecretTemplateHandler_List_Empty(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "templates")
}

func TestSecretTemplateHandler_List_WithTemplates(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	// Pre-create a template.
	createReq := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"my-tmpl"}`)))
	h.Create(httptest.NewRecorder(), createReq)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "my-tmpl")
}

// ── Get ───────────────────────────────────────────────────────────────────────

func TestSecretTemplateHandler_Get_InvalidID(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodGet, "/", nil), "abc")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Get_NotFound(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodGet, "/", nil), "999")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSecretTemplateHandler_Get_Success(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	cw := httptest.NewRecorder()
	h.Create(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"get-me"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	req := stChiID(httptest.NewRequest(http.MethodGet, "/", nil), "1")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "get-me")
}

// ── Update ────────────────────────────────────────────────────────────────────

func TestSecretTemplateHandler_Update_InvalidID(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"name":"x"}`)), "xyz")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Update_InvalidJSON(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Update_NotFound(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"name":"x"}`))), "999")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSecretTemplateHandler_Update_NameRequired(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	cw := httptest.NewRecorder()
	h.Create(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"upd-me"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	req := stChiID(withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"name":""}`))), "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Update_InvalidClassification(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	cw := httptest.NewRecorder()
	h.Create(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"upd-cls"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	body := bytes.NewBufferString(`{"name":"upd-cls","default_classification":"NOPE"}`)
	req := stChiID(withUserCtx(httptest.NewRequest(http.MethodPut, "/", body)), "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Update_Success(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	cw := httptest.NewRecorder()
	h.Create(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"old-name"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	body := bytes.NewBufferString(`{"name":"new-name","default_classification":"internal"}`)
	req := stChiID(withUserCtx(httptest.NewRequest(http.MethodPut, "/", body)), "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "new-name")
}

// ── Delete ────────────────────────────────────────────────────────────────────

func TestSecretTemplateHandler_Delete_InvalidID(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodDelete, "/", nil), "abc")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Delete_NotFound(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodDelete, "/", nil), "999")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSecretTemplateHandler_Delete_Success(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	cw := httptest.NewRecorder()
	h.Create(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"del-me"}`))))
	require.Equal(t, http.StatusCreated, cw.Code)

	req := stChiID(httptest.NewRequest(http.MethodDelete, "/", nil), "1")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── Apply ─────────────────────────────────────────────────────────────────────

func TestSecretTemplateHandler_Apply_InvalidID(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`)), "zz")
	w := httptest.NewRecorder()
	h.Apply(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Apply_InvalidJSON(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "1")
	w := httptest.NewRecorder()
	h.Apply(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretTemplateHandler_Apply_NotFound(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	req := stChiID(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`)), "999")
	w := httptest.NewRecorder()
	h.Apply(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSecretTemplateHandler_Apply_Success(t *testing.T) {
	h := newSecretTemplateTestHandler(t)
	cw := httptest.NewRecorder()
	h.Create(cw, withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		bytes.NewBufferString(`{"name":"apply-me","default_classification":"internal","default_tags":"db"}`))),
	)
	require.Equal(t, http.StatusCreated, cw.Code)

	body := bytes.NewBufferString(`{"classification":"","description":"override"}`)
	req := stChiID(httptest.NewRequest(http.MethodPost, "/", body), "1")
	w := httptest.NewRecorder()
	h.Apply(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
