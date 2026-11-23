package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// approveRiskExceptionWorld is a real core over SQLite with the acting user (1,
// withUserCtx's account) and one pending exception created by another user.
func approveRiskExceptionWorld(t *testing.T) (*DashboardHandler, *gorm.DB, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.AutoMigrate(&models.RiskException{}))
	e := &models.RiskException{Title: "accept for migration", Category: "other", Justification: "temporary",
		CreatedBy: 9, ExpiresAt: time.Now().Add(24 * time.Hour)}
	require.NoError(t, db.Create(e).Error)
	return NewDashboardHandler(cs), db, e.ID
}

func doApproveRiskException(h *DashboardHandler, id uint) *httptest.ResponseRecorder {
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/risk-exceptions/%d/approve", id), nil),
		"id", fmt.Sprint(id)))
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	return w
}

// TestApproveRiskException_InactiveActorIsForbidden: core refuses an acting account
// that is not active (#4546) with a typed permission refusal, answered 403, not 500,
// and the exception stays unapproved.
func TestApproveRiskException_InactiveActorIsForbidden(t *testing.T) {
	h, db, id := approveRiskExceptionWorld(t)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("is_active", false).Error)

	w := doApproveRiskException(h, id)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var e models.RiskException
	require.NoError(t, db.First(&e, id).Error)
	assert.False(t, e.Approved, "a refused approval must not approve the exception")
}

// TestApproveRiskException_ActorReadFaultIs503: a failed read of the acting account
// is a storage fault (#4546, STORAGE-ERR-CLASS-4), answered 503 storage_unavailable
// with Retry-After, not a refusal and not a 500.
func TestApproveRiskException_ActorReadFaultIs503(t *testing.T) {
	h, db, id := approveRiskExceptionWorld(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	w := doApproveRiskException(h, id)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), storageUnavailableCode)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}
