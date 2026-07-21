// rotation_calendar_handler_test.go — HTTP handler tests for
// GET /api/v1/rotation-calendar.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var calendarHandlerCounter atomic.Int64

func freshCalendarDB(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := calendarHandlerCounter.Add(1)
	dsn := fmt.Sprintf("file:kx_cal_handler_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.RotationPolicy{},
	))
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func doCalendarGet(t *testing.T, svc *core.KeyorixCore, from, to string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	url := "/rotation-calendar"
	if from != "" || to != "" {
		url += "?from=" + from + "&to=" + to
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func TestRotationCalendarHandler_MissingParams(t *testing.T) {
	svc, _ := freshCalendarDB(t)
	// Both missing
	rr := doCalendarGet(t, svc, "", "")
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_MissingTo(t *testing.T) {
	svc, _ := freshCalendarDB(t)
	// to is empty: use raw request to avoid including to param
	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-07-01", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_InvalidFrom(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=not-a-date&to=2026-08-31", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_InvalidTo(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-07-01&to=not-a-date", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_FromAfterTo(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-09-01&to=2026-07-01", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRotationCalendarHandler_StorageError(t *testing.T) {
	svc, db := freshCalendarDB(t)

	// Drop the rotation_policies table to force a storage error from GetRotationCalendar.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS rotation_policies").Error)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from=2026-07-01&to=2026-08-31", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRotationCalendarHandler_EmptyResult(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	rr := doCalendarGet(t, svc, "2026-07-01", "2026-08-31")
	assert.Equal(t, http.StatusOK, rr.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.True(t, body["success"].(bool))
}

// Happy path with YYYY-MM-DD format and seeded data verifies JSON structure.
func TestRotationCalendarHandler_WithEntries(t *testing.T) {
	svc, db := freshCalendarDB(t)

	// Seed: project, environment, policy, secret
	proj := &models.Project{Name: "test-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	pol := &models.RotationPolicy{
		Name:         "30-day",
		Scope:        "environment",
		EnvironmentID: &env.ID,
		IntervalDays: 30,
		IsActive:     true,
	}
	require.NoError(t, db.Create(pol).Error)

	// LastRotatedAt = 2026-07-10 → next = 2026-08-09 (within window)
	lastRotated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	secret := &models.SecretNode{
		Name:          "api-key",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		LastRotatedAt: &lastRotated,
	}
	require.NoError(t, db.Create(secret).Error)

	rr := doCalendarGet(t, svc, "2026-07-01", "2026-08-31")
	assert.Equal(t, http.StatusOK, rr.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	data := body["data"].([]interface{})
	require.Len(t, data, 1)

	entry := data[0].(map[string]interface{})
	assert.Equal(t, "api-key", entry["secret_name"])
	assert.Equal(t, float64(30), entry["interval_days"])
	assert.NotEmpty(t, entry["next_rotation_at"])
}

// RFC 3339 timestamps are also accepted as from/to values.
func TestRotationCalendarHandler_RFC3339Format(t *testing.T) {
	svc, _ := freshCalendarDB(t)

	r := chi.NewRouter()
	h := NewRotationCalendarHandler(svc)
	r.Get("/rotation-calendar", h.Get)

	from := "2026-07-01T00:00:00Z"
	to := "2026-08-31T23:59:59Z"
	req := httptest.NewRequest(http.MethodGet, "/rotation-calendar?from="+from+"&to="+to, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}
