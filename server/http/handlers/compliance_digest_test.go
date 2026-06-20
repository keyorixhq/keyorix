package handlers

import (
	"net/http"
	"net/http/httptest"
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

func TestGetComplianceDigestHandler(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// The migration set GetCompliancePosture (which the digest builds on) reads from.
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.AuditEvent{}, &models.AnomalyAlert{}, &models.LegalHold{},
		&models.SoDPolicy{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{}, &models.AccessRequest{}, &models.RiskException{},
	))

	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	t.Run("returns the on-demand digest title and body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/digest", nil)
		w := httptest.NewRecorder()
		h.GetComplianceDigest(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, `"title"`)
		assert.Contains(t, body, `"body"`)
		// The digest title + posture summary lines come through.
		assert.Contains(t, body, "Keyorix compliance digest")
		assert.Contains(t, body, "Controls:")
		assert.Contains(t, body, "Classification:")
	})
}
