package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOwnershipHistory_Unauthorized(t *testing.T) {
	h, err := NewSecretHandler(freshCoreS12(t))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	h.OwnershipHistory(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOwnershipHistory_InvalidID(t *testing.T) {
	h, err := NewSecretHandler(freshCoreS12(t))
	require.NoError(t, err)
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanid"))
	w := httptest.NewRecorder()
	h.OwnershipHistory(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOwnershipHistory_NotFound(t *testing.T) {
	h, err := NewSecretHandler(freshCoreS12(t))
	require.NoError(t, err)
	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "99999"))
	w := httptest.NewRecorder()
	h.OwnershipHistory(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestOwnershipHistory_EmptyHistory(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	secret := &models.SecretNode{
		Name:     "test-secret",
		OwnerID:  1, // matches withUserCtx's UserID
		IsSecret: true,
	}
	require.NoError(t, db.Create(secret).Error)

	r := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", secret.ID)))
	w := httptest.NewRecorder()
	h.OwnershipHistory(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}
