package handlers

import (
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

func TestExportComplianceControlsCSV(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.AuditEvent{}, &models.AnomalyAlert{}, &models.LegalHold{},
		&models.SoDPolicy{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{}, &models.AccessRequest{}, &models.RiskException{},
	))

	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	t.Run("returns the control matrix as a CSV with framework refs", func(t *testing.T) {
		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/controls.csv", nil))
		w := httptest.NewRecorder()
		h.ExportComplianceControlsCSV(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
		assert.Contains(t, w.Header().Get("Content-Disposition"), "compliance-controls.csv")

		body := w.Body.String()
		lines := strings.Split(strings.TrimSpace(body), "\n")
		require.GreaterOrEqual(t, len(lines), 2, "header + at least one control")
		assert.Equal(t, "id,name,area,status,detail,iso_27001,soc2,nis2,dora", strings.TrimSpace(lines[0]))
		// The tamper-evident audit-trail control and its ISO ref come through.
		assert.Contains(t, body, "audit-trail-integrity")
		assert.Contains(t, body, "A.5.28")
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/controls.csv", nil)
		w := httptest.NewRecorder()
		h.ExportComplianceControlsCSV(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
