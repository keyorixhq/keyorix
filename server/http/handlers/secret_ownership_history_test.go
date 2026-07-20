package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
