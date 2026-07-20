package handlers

import (
	"bytes"
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

func newVersionCommentTestHandler(t *testing.T) *SecretVersionCommentHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretVersionComment{}))
	return NewSecretVersionCommentHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

func TestCreateComment_Unauthorized(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	w := httptest.NewRecorder()
	h.CreateComment(w, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateComment_InvalidSecretID(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "bad", "versionId": "1"}))
	w := httptest.NewRecorder()
	h.CreateComment(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateComment_InvalidVersionID(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "1", "versionId": "bad"}))
	w := httptest.NewRecorder()
	h.CreateComment(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateComment_Success(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	body := bytes.NewBufferString(`{"comment":"test annotation"}`)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body), map[string]string{"id": "1", "versionId": "1"}))
	w := httptest.NewRecorder()
	h.CreateComment(w, r)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestCreateComment_EmptyComment(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	body := bytes.NewBufferString(`{"comment":""}`)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body), map[string]string{"id": "1", "versionId": "1"}))
	w := httptest.NewRecorder()
	h.CreateComment(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListComments_InvalidVersionID(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "1", "versionId": "bad"}))
	w := httptest.NewRecorder()
	h.ListComments(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListComments_Unauthorized(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	w := httptest.NewRecorder()
	h.ListComments(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListComments_InvalidSecretID(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "bad", "versionId": "1"}))
	w := httptest.NewRecorder()
	h.ListComments(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListComments_Empty(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "1", "versionId": "1"}))
	w := httptest.NewRecorder()
	h.ListComments(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteComment_Unauthorized(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	w := httptest.NewRecorder()
	h.DeleteComment(w, httptest.NewRequest(http.MethodDelete, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteComment_InvalidCommentID(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "versionId": "1", "commentId": "bad"}))
	w := httptest.NewRecorder()
	h.DeleteComment(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteComment_NotFound(t *testing.T) {
	h := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "versionId": "1", "commentId": "999"}))
	w := httptest.NewRecorder()
	h.DeleteComment(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)
}
