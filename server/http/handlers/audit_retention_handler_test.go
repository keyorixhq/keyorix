package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// auditRetentionDBCounter makes each in-memory DB unique within the process.
var auditRetentionDBCounter atomic.Int64

// newAuditRetentionHandler builds an AdminJobsHandler backed by a fresh
// in-memory SQLite DB with the AuditEvent schema migrated.
func newAuditRetentionHandler(t *testing.T) *AdminJobsHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := auditRetentionDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_auditretention_%d?mode=memory&cache=shared&_busy_timeout=5000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	return NewAdminJobsHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

// postPurgeAuditLogs sends a POST request directly to PurgeAuditLogsJob.
func postPurgeAuditLogs(h http.HandlerFunc, body interface{}, auth bool) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/admin/jobs/purge-audit-logs", &buf)
	req.Header.Set("Content-Type", "application/json")
	if auth {
		req = withUserCtx(req)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// TestPurgeAuditLogsHandler_HappyPath verifies 200 + deleted_count in the response.
func TestPurgeAuditLogsHandler_HappyPath(t *testing.T) {
	h := newAuditRetentionHandler(t)
	w := postPurgeAuditLogs(h.PurgeAuditLogsJob,
		map[string]interface{}{"retention_days": 30}, true)

	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	assert.Equal(t, float64(0), data["deleted_count"], "empty DB → zero deleted")
	assert.NotNil(t, data["cutoff_time"], "cutoff_time is present")
}

// TestPurgeAuditLogsHandler_BelowMinimum verifies 400 when retention_days < 7.
func TestPurgeAuditLogsHandler_BelowMinimum(t *testing.T) {
	h := newAuditRetentionHandler(t)

	for _, days := range []int{0, 1, 6} {
		w := postPurgeAuditLogs(h.PurgeAuditLogsJob,
			map[string]interface{}{"retention_days": days}, true)
		assert.Equal(t, http.StatusBadRequest, w.Code, "days=%d should return 400", days)
	}
}

// TestPurgeAuditLogsHandler_RequiresAuth verifies 401 when no user context.
func TestPurgeAuditLogsHandler_RequiresAuth(t *testing.T) {
	h := newAuditRetentionHandler(t)
	w := postPurgeAuditLogs(h.PurgeAuditLogsJob,
		map[string]interface{}{"retention_days": 30}, false)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestPurgeAuditLogsHandler_InvalidJSON verifies 400 on malformed JSON.
func TestPurgeAuditLogsHandler_InvalidJSON(t *testing.T) {
	h := newAuditRetentionHandler(t)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/admin/jobs/purge-audit-logs",
		bytes.NewReader([]byte("{bad")))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.PurgeAuditLogsJob(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPurgeAuditLogsHandler_StorageError verifies 500 when the DB is closed.
func TestPurgeAuditLogsHandler_StorageError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	n := auditRetentionDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_auditretention_%d?mode=memory&cache=shared&_busy_timeout=5000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	h := NewAdminJobsHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	w := postPurgeAuditLogs(h.PurgeAuditLogsJob,
		map[string]interface{}{"retention_days": 30}, true)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
