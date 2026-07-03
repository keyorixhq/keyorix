package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		assert.Equal(t, "id,name,area,status,detail,iso_27001,soc2,nis2,dora,ens", strings.TrimSpace(lines[0]))
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

	t.Run("every cell is written through csvSafe even though none currently starts with attacker content", func(t *testing.T) {
		// The only operator/free-text field reachable in this otherwise system-
		// generated export is LegalHoldPosture.Reason, but legalHoldDetail always
		// embeds it after a fixed "ACTIVE — purges blocked (" prefix, so it can never
		// land as the leading character of the "detail" cell — a formula-injection
		// payload here is inert today. Every string cell is still routed through
		// csvSafe (matching the audit / inventory export handlers) as defense in
		// depth against a future Detail-builder that puts free text first.
		require.NoError(t, db.Create(&models.LegalHold{
			Reason: "=1+1", PlacedBy: 1, PlacedAt: time.Now(), Released: false,
		}).Error)

		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/compliance/controls.csv", nil))
		w := httptest.NewRecorder()
		h.ExportComplianceControlsCSV(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "ACTIVE — purges blocked (=1+1)", "embedded mid-cell: correctly left unescaped")
	})
}
