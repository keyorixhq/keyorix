// audit_request_id_handler_test.go — AUDIT-REQUEST-ID-2 item 1: request_id in the
// audit list, search and export responses, and the request_id= filter
// (docs/specs/audit-request-id.md §8).
package handlers

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	reqIDAllowed = "0123456789abcdef01234567"
	reqIDRefused = "fedcba9876543210fedcba98"
)

func seedAuditEventWithRequestID(t *testing.T, db *gorm.DB, eventType string, success bool, requestID string) {
	t.Helper()
	e := &models.AuditEvent{EventType: eventType, Success: &success, EventTime: time.Now()}
	if requestID != "" {
		e.RequestID = &requestID
	}
	require.NoError(t, db.Create(e).Error)
}

// seedRequestIDEvents writes one row of a served request, one of a refused request
// (Success=false) and one without any request id.
func seedRequestIDEvents(t *testing.T, db *gorm.DB) {
	t.Helper()
	seedAuditEventWithRequestID(t, db, "secret.created", true, reqIDAllowed)
	seedAuditEventWithRequestID(t, db, "auth.login_failed", false, reqIDRefused)
	seedAuditEventWithRequestID(t, db, "system.tick", true, "")
}

func getAuditJSON(t *testing.T, serve http.HandlerFunc, target, key string) []map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	serve(w, withUserCtx(httptest.NewRequest(http.MethodGet, target, nil)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var env struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	var rows []map[string]any
	require.NoError(t, json.Unmarshal(env.Data[key], &rows))
	return rows
}

func TestAuditLogs_RequestIDFieldAndFilter(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedRequestIDEvents(t, db)
	h := NewAuditHandler(cs)

	// Unfiltered: every row, the id only where there is one (omitted when NULL).
	all := getAuditJSON(t, h.GetAuditLogs, "/api/v1/audit/logs", "logs")
	require.Len(t, all, 3)
	byType := map[string]map[string]any{}
	for _, r := range all {
		byType[r["event_type"].(string)] = r
	}
	assert.Equal(t, reqIDAllowed, byType["secret.created"]["request_id"])
	assert.Equal(t, reqIDRefused, byType["auth.login_failed"]["request_id"])
	_, present := byType["system.tick"]["request_id"]
	assert.False(t, present, "a row without a request id omits the field")

	// The refused request's row is found by its id.
	got := getAuditJSON(t, h.GetAuditLogs, "/api/v1/audit/logs?request_id="+reqIDRefused, "logs")
	require.Len(t, got, 1)
	assert.Equal(t, "auth.login_failed", got[0]["event_type"])
	assert.Equal(t, reqIDRefused, got[0]["request_id"])

	// Exact match: a prefix matches nothing.
	assert.Empty(t, getAuditJSON(t, h.GetAuditLogs, "/api/v1/audit/logs?request_id="+reqIDRefused[:10], "logs"))
}

func TestAuditSearch_RequestIDFilter(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedRequestIDEvents(t, db)
	h := NewAuditHandler(cs)

	got := getAuditJSON(t, h.SearchAuditLogs, "/api/v1/audit/search?request_id="+reqIDAllowed, "events")
	require.Len(t, got, 1)
	assert.Equal(t, "secret.created", got[0]["event_type"])
	assert.Equal(t, reqIDAllowed, got[0]["request_id"])

	got = getAuditJSON(t, h.SearchAuditLogs, "/api/v1/audit/search?request_id="+reqIDRefused, "events")
	require.Len(t, got, 1)
	assert.Equal(t, "auth.login_failed", got[0]["event_type"])

	assert.Empty(t, getAuditJSON(t, h.SearchAuditLogs, "/api/v1/audit/search?request_id=nope", "events"))
}

func TestAuditExport_CarriesRequestID(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedRequestIDEvents(t, db)
	h := NewAuditHandler(cs)

	// JSON feed.
	rows := getAuditJSON(t, h.ExportAuditLogs, "/api/v1/audit/export", "events")
	ids := map[string]string{}
	for _, r := range rows {
		id, _ := r["request_id"].(string)
		ids[r["event_type"].(string)] = id
	}
	assert.Equal(t, map[string]string{
		"secret.created": reqIDAllowed, "auth.login_failed": reqIDRefused, "system.tick": "",
	}, ids)

	// CSV: a request_id column, empty for the row without one.
	w := httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil)))
	require.Equal(t, http.StatusOK, w.Code)
	recs, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	require.NoError(t, err)
	require.Len(t, recs, 4)
	col := -1
	for i, name := range recs[0] {
		if name == "request_id" {
			col = i
		}
	}
	require.GreaterOrEqual(t, col, 0, "header: %v", recs[0])
	typeCol := 2 // event_type
	got := map[string]string{}
	for _, rec := range recs[1:] {
		got[rec[typeCol]] = rec[col]
	}
	assert.Equal(t, ids, got)
}

// The CSV column is escaped like every text column: a value that would be read as a
// formula by a spreadsheet is neutralised (the column is server-minted, but the
// export must not depend on that).
func TestAuditExportCSV_RequestIDIsFormulaEscaped(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditEventWithRequestID(t, db, "secret.created", true, "=1+1")
	h := NewAuditHandler(cs)

	w := httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export.csv", nil)))
	require.Equal(t, http.StatusOK, w.Code)
	recs, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	require.NoError(t, err)
	require.Len(t, recs, 2)
	last := recs[1][len(recs[1])-1]
	assert.NotEqual(t, "=1+1", last)
	assert.False(t, strings.HasPrefix(last, "="), "got %q", last)
}
