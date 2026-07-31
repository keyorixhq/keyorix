package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func newSnapshotHandlerDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.AuditEvent{}, &models.AnomalyAlert{}, &models.LegalHold{},
		&models.SoDPolicy{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{}, &models.AccessRequest{}, &models.RiskException{},
		&models.CompliancePostureSnapshot{},
	))
	return db
}

func TestTakeComplianceSnapshot_HandlerSuccess(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/snapshots", nil)
	w := httptest.NewRecorder()
	h.TakeComplianceSnapshot(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			SnapshotDate string `json:"snapshot_date"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

func TestTakeComplianceSnapshot_HandlerError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	// Drop projects so GetCompliancePosture (first call inside TakeComplianceSnapshot) errors.
	require.NoError(t, db.Exec("DROP TABLE projects").Error)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/snapshots", nil)
	w := httptest.NewRecorder()
	h.TakeComplianceSnapshot(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}

func TestListComplianceSnapshots_HandlerNoLimit(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool        `json:"success"`
		Data    interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

func TestListComplianceSnapshots_HandlerWithLimit(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots?limit=2", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"success":true`)
}

func TestListComplianceSnapshots_HandlerInvalidLimitNegative(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots?limit=-1", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

func TestListComplianceSnapshots_HandlerInvalidLimitNonNumeric(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots?limit=abc", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

func TestListComplianceSnapshots_HandlerStorageError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := newSnapshotHandlerDB(t)
	// Drop the snapshots table so the storage query errors.
	require.NoError(t, db.Exec("DROP TABLE compliance_posture_snapshots").Error)
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/snapshots", nil)
	w := httptest.NewRecorder()
	h.ListComplianceSnapshots(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}
