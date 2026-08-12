package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// versionCommentFixture is a handler wired to two distinct secrets, each with
// its own version, so cross-secret sub-resource-ID checks (#G53) can be
// exercised at the handler layer.
type versionCommentFixture struct {
	handler               *SecretVersionCommentHandler
	secretAID, versionAID uint
	secretBID, versionBID uint
}

func newVersionCommentTestHandler(t *testing.T) *versionCommentFixture {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.SecretVersionComment{}))

	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "secret-a", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)
	versionA := &models.SecretVersion{SecretNodeID: 1, VersionNumber: 1}
	require.NoError(t, db.Create(versionA).Error)

	require.NoError(t, db.Create(&models.SecretNode{
		ID: 2, Name: "secret-b", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)
	versionB := &models.SecretVersion{SecretNodeID: 2, VersionNumber: 1}
	require.NoError(t, db.Create(versionB).Error)

	return &versionCommentFixture{
		handler:    NewSecretVersionCommentHandler(core.NewKeyorixCore(store.NewLocalStorage(db))),
		secretAID:  1,
		versionAID: versionA.ID,
		secretBID:  2,
		versionBID: versionB.ID,
	}
}

func TestCreateComment_Unauthorized(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	w := httptest.NewRecorder()
	f.handler.CreateComment(w, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateComment_InvalidSecretID(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "bad", "versionId": "1"}))
	w := httptest.NewRecorder()
	f.handler.CreateComment(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateComment_InvalidVersionID(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "1", "versionId": "bad"}))
	w := httptest.NewRecorder()
	f.handler.CreateComment(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateComment_Success(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	body := bytes.NewBufferString(`{"comment":"test annotation"}`)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body), chiParamsForVersion(f.secretAID, f.versionAID)))
	w := httptest.NewRecorder()
	f.handler.CreateComment(w, r)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestCreateComment_EmptyComment(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	body := bytes.NewBufferString(`{"comment":""}`)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body), chiParamsForVersion(f.secretAID, f.versionAID)))
	w := httptest.NewRecorder()
	f.handler.CreateComment(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateComment_VersionBelongsToAnotherSecret is the #G53 regression:
// versionId in the URL actually belongs to secret B, not the {id} (secret A)
// the caller was authorized against — must be refused, not silently written
// under secret A's authorization.
func TestCreateComment_VersionBelongsToAnotherSecret(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	body := bytes.NewBufferString(`{"comment":"cross-tenant write"}`)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body), chiParamsForVersion(f.secretAID, f.versionBID)))
	w := httptest.NewRecorder()
	f.handler.CreateComment(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListComments_InvalidVersionID(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "1", "versionId": "bad"}))
	w := httptest.NewRecorder()
	f.handler.ListComments(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListComments_Unauthorized(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	w := httptest.NewRecorder()
	f.handler.ListComments(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListComments_InvalidSecretID(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "bad", "versionId": "1"}))
	w := httptest.NewRecorder()
	f.handler.ListComments(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListComments_Empty(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), chiParamsForVersion(f.secretAID, f.versionAID)))
	w := httptest.NewRecorder()
	f.handler.ListComments(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

// TestListComments_VersionBelongsToAnotherSecret is the #G53 regression: the
// caller is authorized on secret A ({id}) but supplies secret B's versionId —
// must be refused rather than disclosing secret B's comments.
func TestListComments_VersionBelongsToAnotherSecret(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), chiParamsForVersion(f.secretAID, f.versionBID)))
	w := httptest.NewRecorder()
	f.handler.ListComments(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteComment_Unauthorized(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	w := httptest.NewRecorder()
	f.handler.DeleteComment(w, httptest.NewRequest(http.MethodDelete, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteComment_InvalidCommentID(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	params := chiParamsForVersion(f.secretAID, f.versionAID)
	params["commentId"] = "bad"
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params))
	w := httptest.NewRecorder()
	f.handler.DeleteComment(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteComment_NotFound: secret/version are real and authorized, but no
// comment with that ID exists under them. Since local_version_comments.go's
// DeleteSecretVersionComment now scopes the delete to secret_id/version_id
// AND reports RowsAffected==0 as not-found (#G53), this is no longer a silent
// no-op success — it surfaces as an error, same as any other core failure
// this handler maps to 500.
func TestDeleteComment_NotFound(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	params := chiParamsForVersion(f.secretAID, f.versionAID)
	params["commentId"] = "999"
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params))
	w := httptest.NewRecorder()
	f.handler.DeleteComment(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestDeleteComment_VersionBelongsToAnotherSecret is the #G53 regression for
// delete: the caller is authorized on secret A but supplies secret B's
// versionId — must be refused before any delete is attempted.
func TestDeleteComment_VersionBelongsToAnotherSecret(t *testing.T) {
	f := newVersionCommentTestHandler(t)
	params := chiParamsForVersion(f.secretAID, f.versionBID)
	params["commentId"] = "1"
	r := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params))
	w := httptest.NewRecorder()
	f.handler.DeleteComment(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func chiParamsForVersion(secretID, versionID uint) map[string]string {
	return map[string]string{
		"id":        fmt.Sprintf("%d", secretID),
		"versionId": fmt.Sprintf("%d", versionID),
	}
}
