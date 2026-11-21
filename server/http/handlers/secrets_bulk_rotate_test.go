// secrets_bulk_rotate_test.go — coverage for BulkRotateSecrets
// (secrets_bulk_rotate.go), previously untested (0% coverage).
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// seedBulkRotateActor creates the active account withUserCtx authenticates as:
// core refuses an acting account that is not active (#4159), and does so before
// it validates the request.
func seedBulkRotateActor(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "bulk-rotate-actor", UsernameFolded: "bulk-rotate-actor",
		Email: "bulk-rotate-actor@example.com", EmailFolded: "bulk-rotate-actor@example.com", IsActive: true}).Error)
}

func TestBulkRotateSecrets_Unauthorized(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate", nil), "id", "1")
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBulkRotateSecrets_InvalidProjectID(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/abc/secrets/bulk-rotate", nil), "id", "abc")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBulkRotateSecrets_BadJSON(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate",
		bytes.NewReader([]byte("{bad json}"))), "id", "1")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBulkRotateSecrets_BatchTooLarge exercises the "exceeds the maximum
// batch size" -> 400 branch (core.maxBulkRotateBatchSize is 500).
func TestBulkRotateSecrets_BatchTooLarge(t *testing.T) {
	h, db := newProjectHealthHandler(t)
	seedBulkRotateActor(t, db)
	ids := make([]uint, 501)
	for i := range ids {
		ids[i] = uint(i + 1)
	}
	body, _ := json.Marshal(map[string]any{"secret_ids": ids})
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate",
		bytes.NewReader(body)), "id", "1")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBulkRotateSecrets_Success — an empty project (no secrets, no explicit
// secret_ids) is a legal project-wide rotation of zero secrets: 200 with an
// empty Triggered/Failed result.
func TestBulkRotateSecrets_Success(t *testing.T) {
	h, db := newProjectHealthHandler(t)
	seedBulkRotateActor(t, db)
	body, _ := json.Marshal(map[string]any{})
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate",
		bytes.NewReader(body)), "id", "1")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Total int `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

// bulkRotateEmpty sends an empty project-wide bulk rotation as withUserCtx's
// account and returns the recorder.
func bulkRotateEmpty(t *testing.T, h *SecretHandler) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{})
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate",
		bytes.NewReader(body)), "id", "1")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	return w
}

// TestBulkRotateSecrets_InactiveActorIsForbidden: core refuses an acting account
// that is not active (#4159) with a typed permission refusal, which the handler
// answers 403, not 500. A missing account is the same refusal.
func TestBulkRotateSecrets_InactiveActorIsForbidden(t *testing.T) {
	t.Run("deactivated", func(t *testing.T) {
		h, db := newProjectHealthHandler(t)
		seedBulkRotateActor(t, db)
		require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("is_active", false).Error)
		w := bulkRotateEmpty(t, h)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})
	t.Run("no such account", func(t *testing.T) {
		h, _ := newProjectHealthHandler(t)
		w := bulkRotateEmpty(t, h)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})
}

// TestBulkRotateSecrets_ActorReadFaultIs503: a failed read of the acting account
// is a storage fault (STORAGE-ERR-CLASS-4), answered 503 storage_unavailable with
// Retry-After, not a refusal and not a 500.
func TestBulkRotateSecrets_ActorReadFaultIs503(t *testing.T) {
	h, db := newProjectHealthHandler(t)
	seedBulkRotateActor(t, db)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	w := bulkRotateEmpty(t, h)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), storageUnavailableCode)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}
