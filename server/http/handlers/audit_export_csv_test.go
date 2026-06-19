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

func TestExportAuditLogsCSV(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@t.com"}).Error)

	uid := uint(1)
	pid := uint(5)
	tru := true
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.created", UserID: &uid, ProjectID: &pid, Success: &tru,
		Description: "created db", IPAddress: "10.0.0.1", EventTime: time.Now(),
	}).Error)

	h := NewAuditHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	t.Run("returns a CSV attachment with a header and the event", func(t *testing.T) {
		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil))
		w := httptest.NewRecorder()
		h.ExportAuditLogsCSV(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
		assert.Contains(t, w.Header().Get("Content-Disposition"), "audit-export.csv")

		body := w.Body.String()
		lines := strings.Split(strings.TrimSpace(body), "\n")
		require.GreaterOrEqual(t, len(lines), 2)
		assert.Equal(t, "id,event_time,event_type,actor,actor_type,user_id,project_id,secret_id,ip_address,success,description", strings.TrimSpace(lines[0]))
		assert.Contains(t, body, "secret.created")
		assert.Contains(t, body, "alice")
		assert.Contains(t, body, "created db")
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil)
		w := httptest.NewRecorder()
		h.ExportAuditLogsCSV(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
