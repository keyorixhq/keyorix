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

func newAdminJobsHandler(t *testing.T) *AdminJobsHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// Union of what the lightweight jobs touch (anomaly / rotation / expiry).
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.Notification{}, &models.RotationPolicy{},
		&models.AnomalyAlert{}, &models.AuditEvent{},
	))
	return NewAdminJobsHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

func postJob(h http.HandlerFunc, target string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, nil)
	if auth {
		req = withUserCtx(req)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func TestAdminJobsHandlers_HappyPath(t *testing.T) {
	h := newAdminJobsHandler(t)

	t.Run("anomaly-alerts returns alerted count on empty state", func(t *testing.T) {
		w := postJob(h.RunAnomalyAlerts, "/api/v1/admin/jobs/anomaly-alerts", true)
		require.Equal(t, http.StatusOK, w.Code)
		assert.EqualValues(t, 0, decodeData(t, w)["alerted"])
	})

	t.Run("rotation-reminders returns sent count", func(t *testing.T) {
		w := postJob(h.RunRotationReminders, "/api/v1/admin/jobs/rotation-reminders", true)
		require.Equal(t, http.StatusOK, w.Code)
		assert.EqualValues(t, 0, decodeData(t, w)["sent"])
	})

	t.Run("expiry-reminders honors lead_days and returns sent count", func(t *testing.T) {
		w := postJob(h.RunExpiryReminders, "/api/v1/admin/jobs/expiry-reminders?lead_days=30", true)
		require.Equal(t, http.StatusOK, w.Code)
		assert.EqualValues(t, 0, decodeData(t, w)["sent"])
	})

	t.Run("role-expiry-check returns zero counters on empty state", func(t *testing.T) {
		w := postJob(h.RunRoleExpiryCheck, "/api/v1/admin/jobs/role-expiry-check", true)
		require.Equal(t, http.StatusOK, w.Code)
		d := decodeData(t, w)
		assert.EqualValues(t, 0, d["warnings"])
		assert.EqualValues(t, 0, d["criticals"])
	})
}

func TestAdminJobsHandlers_RequireUserContext(t *testing.T) {
	h := newAdminJobsHandler(t)
	cases := map[string]http.HandlerFunc{
		"anomaly-alerts":     h.RunAnomalyAlerts,
		"rotation-reminders": h.RunRotationReminders,
		"expiry-reminders":   h.RunExpiryReminders,
		"compliance-digest":  h.RunComplianceDigest,
		"role-expiry-check":  h.RunRoleExpiryCheck,
	}
	for name, fn := range cases {
		t.Run(name+" is unauthorized without a user context", func(t *testing.T) {
			w := postJob(fn, "/api/v1/admin/jobs/"+name, false)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}
