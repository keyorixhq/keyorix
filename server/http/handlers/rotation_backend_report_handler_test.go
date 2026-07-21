// rotation_backend_report_handler_test.go — unit tests for RotationByBackend handler.
// Tests the 401 (no user ctx), 500 (core error), and 200 (success) branches.
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

var rbhDBCounter atomic.Int64

// freshCoreRBH opens a uniquely-named in-memory SQLite DB and returns a ready-to-use
// KeyorixCore for rotation_backend_report_handler tests.
func freshCoreRBH(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := rbhDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_rbh_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.RotationPolicy{}, &models.SystemMetadata{},
		&models.Session{}, &models.SecretVersion{},
	)
	require.NoError(t, err)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// freshCoreRBHClosed returns a core backed by a closed DB to trigger storage errors.
func freshCoreRBHClosed(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := rbhDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_rbh_closed_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(&models.RotationPolicy{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	_ = sqlDB.Close()
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// TestRotationByBackend_NoUserCtx — nil user context produces a 401.
func TestRotationByBackend_NoUserCtx(t *testing.T) {
	cs := freshCoreRBH(t)
	h := &SecretHandler{coreService: cs}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/rotation-by-backend", nil)
	w := httptest.NewRecorder()
	h.RotationByBackend(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRotationByBackend_Success — authenticated request against an empty DB produces 200.
func TestRotationByBackend_Success(t *testing.T) {
	cs := freshCoreRBH(t)
	h := &SecretHandler{coreService: cs}

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/rotation-by-backend", nil))
	w := httptest.NewRecorder()
	h.RotationByBackend(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRotationByBackend_StorageError — a closed DB causes GetRotationBackendReport
// to error; the handler must respond with 500.
func TestRotationByBackend_StorageError(t *testing.T) {
	cs := freshCoreRBHClosed(t)
	h := &SecretHandler{coreService: cs}

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/rotation-by-backend", nil))
	w := httptest.NewRecorder()
	h.RotationByBackend(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
