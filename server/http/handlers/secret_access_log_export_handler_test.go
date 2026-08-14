// secret_access_log_export_handler_test.go — HTTP handler tests for
// GET /api/v1/secrets/{id}/access-log/export
package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

var exportHandlerCounter atomic.Int64

func freshExportDB(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := exportHandlerCounter.Add(1)
	dsn := fmt.Sprintf("file:kx_export_handler_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.AuditEvent{},
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.MachineIdentityRole{}, &models.SecretACL{},
	))
	// #G10: ExportSecretAccessLog now self-authorizes; withUserCtx's UserID 1 is granted
	// global admin so these handler tests keep exercising the glue logic (param parsing,
	// status-code mapping), not authorization.
	role := &models.Role{Name: "admin"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func doExportGet(t *testing.T, svc *core.KeyorixCore, secretID uint, queryParams string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	h, err := NewSecretHandler(svc)
	require.NoError(t, err)

	// Mounted at the real API path (matching router.go), not a shortened
	// local one -- the OpenAPI contract harness resolves operations by the
	// request's actual URL path, which must match what the spec declares.
	r := chi.NewRouter()
	r.Get("/api/v1/secrets/{id}/access-log/export", h.ExportAccessLog)

	url := fmt.Sprintf("/api/v1/secrets/%d/access-log/export", secretID)
	if queryParams != "" {
		url += "?" + queryParams
	}
	req := withUserCtx(httptest.NewRequest(http.MethodGet, url, nil))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr, req
}

func seedSecretAndEvents(t *testing.T, db *gorm.DB) uint {
	t.Helper()
	proj := &models.Project{Name: "test-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name:          "my-secret",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
	}
	require.NoError(t, db.Create(secret).Error)

	uid := uint(1)
	sTrue := true
	ev := &models.AuditEvent{
		EventType:    "secret.read",
		UserID:       &uid,
		SecretNodeID: &secret.ID,
		ProjectID:    &proj.ID,
		IPAddress:    "127.0.0.1",
		Success:      &sTrue,
		ActorType:    "user",
		EventTime:    time.Now().UTC(),
	}
	require.NoError(t, db.Create(ev).Error)
	return secret.ID
}

func TestExportAccessLog_InvalidID(t *testing.T) {
	svc, _ := freshExportDB(t)
	h, err := NewSecretHandler(svc)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Get("/secrets/{id}/access-log/export", h.ExportAccessLog)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/secrets/not-a-number/access-log/export", nil))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestExportAccessLog_Unauthenticated is #G10: this handler used to have no identity
// check at all — the export ran with zero authorization, correctness depending entirely
// on router wiring elsewhere.
func TestExportAccessLog_Unauthenticated(t *testing.T) {
	svc, db := freshExportDB(t)
	secretID := seedSecretAndEvents(t, db)

	rr, _ := doExportGetNoAuth(t, svc, secretID, "")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func doExportGetNoAuth(t *testing.T, svc *core.KeyorixCore, secretID uint, queryParams string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	h, err := NewSecretHandler(svc)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Get("/api/v1/secrets/{id}/access-log/export", h.ExportAccessLog)

	url := fmt.Sprintf("/api/v1/secrets/%d/access-log/export", secretID)
	if queryParams != "" {
		url += "?" + queryParams
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr, req
}

func TestExportAccessLog_SecretNotFound(t *testing.T) {
	svc, _ := freshExportDB(t)
	rr, _ := doExportGet(t, svc, 9999, "")
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestExportAccessLog_InvalidFormat(t *testing.T) {
	svc, db := freshExportDB(t)
	secretID := seedSecretAndEvents(t, db)

	rr, _ := doExportGet(t, svc, secretID, "format=xlsx")
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestExportAccessLog_StorageError(t *testing.T) {
	svc, db := freshExportDB(t)
	secretID := seedSecretAndEvents(t, db)

	// Drop audit_events to force an error from GetAuditLogs.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS audit_events").Error)

	rr, _ := doExportGet(t, svc, secretID, "")
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestExportAccessLog_DefaultFormatJSON(t *testing.T) {
	svc, db := freshExportDB(t)
	secretID := seedSecretAndEvents(t, db)

	// No format param → defaults to json
	rr, _ := doExportGet(t, svc, secretID, "")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")
	assert.Contains(t, rr.Header().Get("Content-Disposition"), fmt.Sprintf("secret-%d-access-log.json", secretID))

	var rows []core.AccessLogExportRow
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
	require.Len(t, rows, 1)
	assert.Equal(t, secretID, rows[0].SecretID)
}

func TestExportAccessLog_JSONFormat(t *testing.T) {
	svc, db := freshExportDB(t)
	secretID := seedSecretAndEvents(t, db)

	rr, req := doExportGet(t, svc, secretID, "format=json")
	contracttest.AssertOpenAPIResponse(t, req, rr)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")

	var rows []core.AccessLogExportRow
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
	require.Len(t, rows, 1)
	assert.Equal(t, "user", rows[0].ActorType)
}

func TestExportAccessLog_CSVFormat(t *testing.T) {
	svc, db := freshExportDB(t)
	secretID := seedSecretAndEvents(t, db)

	rr, req := doExportGet(t, svc, secretID, "format=csv")
	contracttest.AssertOpenAPIResponse(t, req, rr)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, rr.Header().Get("Content-Disposition"), fmt.Sprintf("secret-%d-access-log.csv", secretID))

	csvReader := csv.NewReader(strings.NewReader(rr.Body.String()))
	records, err := csvReader.ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2) // header + 1 data row
	assert.Equal(t, "event_id", records[0][0])
	assert.NotEmpty(t, records[1][0]) // event_id is populated
}
