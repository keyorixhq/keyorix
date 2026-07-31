package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newBlastRadiusHandlerCore creates a minimal isolated core with a seeded
// project, environment, and one secret node so the blast-radius handler can
// return a successful 200 response.
func newBlastRadiusHandlerCore(t *testing.T) (*core.KeyorixCore, uint) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretDependency{},
		&models.AuditEvent{}, &models.ShareRecord{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "my-secret", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), s.ID
}

// TestGetBlastRadius_Unauthenticated verifies that the handler rejects requests
// without an authenticated user context with 401.
func TestGetBlastRadius_Unauthenticated(t *testing.T) {
	h := newSecretHandlerS4(t)
	// No withUserCtx — simulates an unauthenticated request.
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetBlastRadius_BadID verifies that a non-numeric ID returns 400.
func TestGetBlastRadius_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "not-a-number"))
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetBlastRadius_NotFound verifies that looking up a non-existent secret
// returns a non-200 status and not 401 (the handler's core is hit).
func TestGetBlastRadius_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "99999"))
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)
	// Secret does not exist → core returns "not found" → HTTP 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetBlastRadius_HappyPath verifies that a real secret with zero dependents
// returns 200 and the expected JSON envelope.
func TestGetBlastRadius_HappyPath(t *testing.T) {
	c, secretID := newBlastRadiusHandlerCore(t)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil), "id",
		fmt.Sprintf("%d", secretID),
	))
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "total_impact")
	assert.Contains(t, body, "my-secret")
}
