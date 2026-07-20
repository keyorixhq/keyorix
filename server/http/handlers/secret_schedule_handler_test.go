// secret_schedule_handler_test.go — unit tests for the SecretHandler schedule methods.
package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var schedS39Counter atomic.Uint64

func freshCoreSchedule(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := schedS39Counter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_sched_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.SecretAccessSchedule{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	adminRole := &models.Role{Name: "system_admin_sched", Description: "Administrator"}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.User{Username: "testuser_sched", Email: "testuser_sched@example.com", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func mkSchedHandlerSecret(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: name, IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

func withSchedUserCtx(r *http.Request) *http.Request {
	uctx := &customMiddleware.UserContext{
		UserID:   1,
		Username: "testuser_sched",
		Email:    "testuser_sched@example.com",
	}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), uctx))
}

func withSchedChiParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func dropScheduleTable(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS secret_access_schedules").Error)
}

func TestGetSecretSchedule_BadID(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreSchedule(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/abc/schedule", nil),
		"id", "abc",
	))
	w := httptest.NewRecorder()
	h.GetSecretSchedule(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretSchedule_StorageError(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "get-storage-err")
	dropScheduleTable(t, db)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.GetSecretSchedule(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetSecretSchedule_NoSchedule(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "get-no-sched")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.GetSecretSchedule(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetSecretSchedule_HappyPath(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "get-happy")
	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: sid, AllowedDays: "1,2,3,4,5", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}).Error)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.GetSecretSchedule(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "allowed_days")
}

func TestSetSecretSchedule_BadID(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreSchedule(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body := `{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"UTC"}`
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/abc/schedule", bytes.NewBufferString(body)),
		"id", "abc",
	))
	w := httptest.NewRecorder()
	h.SetSecretSchedule(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetSecretSchedule_MalformedJSON(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "set-badjson")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), bytes.NewBufferString("{not json")),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.SetSecretSchedule(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidJSON")
}

func TestSetSecretSchedule_ValidationError(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "set-validation-err")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body := `{"allowed_days":"1,2,3,4,5","start_hour":17,"end_hour":9,"timezone":"UTC"}`
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), bytes.NewBufferString(body)),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.SetSecretSchedule(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetSecretSchedule_StorageError(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "set-storage-err")
	dropScheduleTable(t, db)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body := `{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"UTC"}`
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), bytes.NewBufferString(body)),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.SetSecretSchedule(w, req)
	// A plain DB error is not ErrAccessOutsideSchedule, so isScheduleValidationError
	// returns true and the handler responds with 400.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetSecretSchedule_DefaultTimezone(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "set-default-tz")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body := `{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17}`
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), bytes.NewBufferString(body)),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.SetSecretSchedule(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"UTC"`)
}

func TestSetSecretSchedule_HappyPath(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "set-happy")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	body := `{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"UTC"}`
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), bytes.NewBufferString(body)),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.SetSecretSchedule(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "schedule set")
}

func TestDeleteSecretSchedule_BadID(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreSchedule(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/abc/schedule", nil),
		"id", "abc",
	))
	w := httptest.NewRecorder()
	h.DeleteSecretSchedule(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSecretSchedule_StorageError(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "del-storage-err")
	dropScheduleTable(t, db)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.DeleteSecretSchedule(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteSecretSchedule_Idempotent(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "del-idempotent")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.DeleteSecretSchedule(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "deleted")
}

func TestDeleteSecretSchedule_HappyPath(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreSchedule(t)
	sid := mkSchedHandlerSecret(t, db, "del-happy")
	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: sid, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC",
	}).Error)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withSchedUserCtx(withSchedChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/schedule", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.DeleteSecretSchedule(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "schedule removed")
}

func TestIsScheduleValidationError(t *testing.T) {
	t.Parallel()
	assert.True(t, isScheduleValidationError(fmt.Errorf("end_hour must be greater than start_hour")))
	assert.False(t, isScheduleValidationError(core.ErrAccessOutsideSchedule))
	assert.False(t, isScheduleValidationError(nil))
}
