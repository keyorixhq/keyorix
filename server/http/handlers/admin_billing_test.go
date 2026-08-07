package handlers

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newBillingTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.SecretNode{}, &models.AuditEvent{}))
	return db
}

func licensedBillingCore(t *testing.T, db *gorm.DB) *core.KeyorixCore {
	t.Helper()
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	pub, priv, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-2026", pub))
	token, err := license.Issue(license.License{
		Licensee: "ACME GmbH", Plan: "enterprise",
		Features: []string{license.FeatureBilling},
		IssuedAt: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyID: "license-2026",
	}, priv)
	require.NoError(t, err)
	c.SetLicenseGate(license.NewGate(token, reg, "", 0))
	return c
}

func billingReportURL(from, to, projectID string) string {
	u := "/api/v1/admin/billing/report?from=" + from + "&to=" + to
	if projectID != "" {
		u += "&project_id=" + projectID
	}
	return u
}

func TestAdminBillingHandler_MissingFromParam(t *testing.T) {
	db := newBillingTestDB(t)
	h := NewAdminBillingHandler(licensedBillingCore(t, db))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/billing/report?to=2026-02-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.GetBillingReport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminBillingHandler_MissingToParam(t *testing.T) {
	db := newBillingTestDB(t)
	h := NewAdminBillingHandler(licensedBillingCore(t, db))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/billing/report?from=2026-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.GetBillingReport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminBillingHandler_InvalidFromParam(t *testing.T) {
	db := newBillingTestDB(t)
	h := NewAdminBillingHandler(licensedBillingCore(t, db))

	req := httptest.NewRequest(http.MethodGet, billingReportURL("not-a-date", "2026-02-01T00:00:00Z", ""), nil)
	w := httptest.NewRecorder()
	h.GetBillingReport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminBillingHandler_InvalidProjectID(t *testing.T) {
	db := newBillingTestDB(t)
	h := NewAdminBillingHandler(licensedBillingCore(t, db))

	req := httptest.NewRequest(http.MethodGet,
		billingReportURL("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "abc"), nil)
	w := httptest.NewRecorder()
	h.GetBillingReport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAdminBillingHandler_Unlicensed asserts the license gate is checked BEFORE
// the report is generated, and returns a distinguishable 403 — not the generic
// 500 clientSafe() masks every other error behind. A billing UI needs to tell
// "not licensed" apart from "server broke" to render correctly.
func TestAdminBillingHandler_Unlicensed(t *testing.T) {
	db := newBillingTestDB(t)
	// No SetLicenseGate call: nil gate → HasLicensedFeature is always false.
	h := NewAdminBillingHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet,
		billingReportURL("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", ""), nil)
	w := httptest.NewRecorder()
	h.GetBillingReport(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "commercial license")
}

func TestAdminBillingHandler_Licensed_ReturnsReport(t *testing.T) {
	db := newBillingTestDB(t)
	require.NoError(t, db.Create(&models.Project{Name: "acme-prod"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{Name: "db-password", ProjectID: 1, IsSecret: true}).Error)

	inWindow := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	success := true
	projectID := uint(1)
	userID := uint(7)
	require.NoError(t, db.Create(&models.AuditEvent{
		ProjectID: &projectID, EventType: "secret.read", Success: &success, ActorType: "user",
		UserID: &userID, EventTime: inWindow,
	}).Error)

	h := NewAdminBillingHandler(licensedBillingCore(t, db))
	req := httptest.NewRequest(http.MethodGet,
		billingReportURL("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", ""), nil)
	w := httptest.NewRecorder()
	h.GetBillingReport(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "acme-prod")
	assert.Contains(t, body, `"secret_reads":1`)
	assert.Contains(t, body, `"secret_count":1`)
}
