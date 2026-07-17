// audit_export_csv_s27_test.go — s27 coverage for audit_export_csv.go helpers.
//
// Gaps targeted:
//   - parseAuditCSVLimit with a valid custom limit value
//   - parseAuditCSVFilter with all valid query params (project_id, user_id, since, until)
//   - auditCSVActorName with nil id → returns ""
//   - ExportAuditLogsCSV with a Success=false event → "false" CSV field
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestParseAuditCSVLimit_ValidLimit exercises the branch where the ?limit
// query param is a valid positive integer within csvExportMaxRows.
func TestParseAuditCSVLimit_ValidLimit(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/audit/export.csv?limit=500", nil)
	got := parseAuditCSVLimit(r)
	assert.Equal(t, 500, got)
}

// TestParseAuditCSVLimit_DefaultFallback covers the zero/missing/over-cap paths
// that all fall through to the default 1000.
func TestParseAuditCSVLimit_DefaultFallback(t *testing.T) {
	cases := []string{
		"/audit/export.csv",
		"/audit/export.csv?limit=0",
		"/audit/export.csv?limit=-1",
		"/audit/export.csv?limit=notanumber",
		"/audit/export.csv?limit=99999999",
	}
	for _, u := range cases {
		r := httptest.NewRequest(http.MethodGet, u, nil)
		assert.Equal(t, 1000, parseAuditCSVLimit(r), "url=%s", u)
	}
}

// TestParseAuditCSVFilter_AllParams exercises all four optional query parameters
// when they carry valid values, ensuring each branch sets the corresponding
// filter field.
func TestParseAuditCSVFilter_AllParams(t *testing.T) {
	since := "2025-01-01T00:00:00Z"
	until := "2025-12-31T23:59:59Z"
	u := "/audit/export.csv?project_id=7&user_id=3&since=" + since + "&until=" + until
	r := httptest.NewRequest(http.MethodGet, u, nil)

	f := parseAuditCSVFilter(r)
	require.NotNil(t, f.ProjectID)
	assert.Equal(t, uint(7), *f.ProjectID)
	require.NotNil(t, f.UserID)
	assert.Equal(t, uint(3), *f.UserID)
	require.NotNil(t, f.StartTime)
	require.NotNil(t, f.EndTime)
}

// TestParseAuditCSVFilter_InvalidParams confirms that malformed query param
// values are silently skipped (filter fields remain nil).
func TestParseAuditCSVFilter_InvalidParams(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet,
		"/audit/export.csv?project_id=bad&user_id=bad&since=notadate&until=notadate", nil)
	f := parseAuditCSVFilter(r)
	assert.Nil(t, f.ProjectID)
	assert.Nil(t, f.UserID)
	assert.Nil(t, f.StartTime)
	assert.Nil(t, f.EndTime)
}

// TestAuditCSVActorName_NilID exercises the nil-id early-return branch that
// produces an empty string.
func TestAuditCSVActorName_NilID(t *testing.T) {
	got := auditCSVActorName(map[uint]string{1: "alice"}, nil)
	assert.Equal(t, "", got)
}

// TestExportAuditLogsCSV_SuccessFalse verifies that events with Success=false
// produce "false" in the CSV success column.
func TestExportAuditLogsCSV_SuccessFalse(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))

	fals := false
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "login.failed", Success: &fals,
		EventTime: time.Now(),
	}).Error)

	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.Contains(w.Body.String(), ",false,"), "expected 'false' in CSV body")
}
