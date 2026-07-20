package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPermissionBaseline_Unauthorized(t *testing.T) {
	h := NewDashboardHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.GetPermissionBaseline(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetPermissionBaseline_EmptyDB(t *testing.T) {
	h := NewDashboardHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.GetPermissionBaseline(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestGetPermissionBaselineCSV_Unauthorized(t *testing.T) {
	h := NewDashboardHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.GetPermissionBaselineCSV(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetPermissionBaselineCSV_EmptyDB(t *testing.T) {
	h := NewDashboardHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.GetPermissionBaselineCSV(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "permission-baseline.csv")
	assert.True(t, strings.Contains(w.Body.String(), "user_id"))
}
