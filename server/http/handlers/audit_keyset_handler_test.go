// audit_keyset_handler_test.go — the cursor and bounded-total contract of
// GET /audit/logs and /audit/search, the 400s for the offset cap and a bad
// cursor, the streamed CSV export across batches, and the SIEM export's since
// (docs/specs/audit-list-keyset.md §3). Real in-memory SQLite.
package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type auditListEnvelope struct {
	Data struct {
		Logs       []AuditLogEntry `json:"logs"`
		Events     []AuditLogEntry `json:"events"`
		Total      *int64          `json:"total"`
		TotalExact *bool           `json:"total_exact"`
		TotalPages *int            `json:"total_pages"`
		NextCursor *string         `json:"next_cursor"`
	} `json:"data"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

func seedAuditKeysetRows(t *testing.T, db *gorm.DB, n int, base time.Time) {
	t.Helper()
	rows := make([]*models.AuditEvent, 0, n)
	for i := range n {
		// Pairs of rows share a timestamp, so the id tie-break matters.
		rows = append(rows, &models.AuditEvent{EventType: "secret.read", EventTime: base.Add(time.Duration(i/2) * time.Second)})
	}
	require.NoError(t, db.CreateInBatches(rows, 500).Error)
	require.NoError(t, store.EnsureAuditListIndexesSQLite(db, t.Logf))
}

func callAudit(t *testing.T, h http.HandlerFunc, path string, q url.Values) (int, auditListEnvelope, string) {
	t.Helper()
	req := withUserCtx(httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil))
	w := httptest.NewRecorder()
	h(w, req)
	var env auditListEnvelope
	if w.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), w.Body.String())
	}
	return w.Code, env, w.Body.String()
}

func TestAuditLogs_CursorWalkAndTotals(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditKeysetRows(t, db, 35, time.Now().UTC().Add(-time.Hour))
	h := NewAuditHandler(cs)

	code, first, _ := callAudit(t, h.GetAuditLogs, "/api/v1/audit/logs", url.Values{"page_size": {"10"}})
	require.Equal(t, http.StatusOK, code)
	require.EqualValues(t, 35, *first.Data.Total)
	require.True(t, *first.Data.TotalExact)
	require.Equal(t, 4, *first.Data.TotalPages)
	require.NotNil(t, first.Data.NextCursor)

	seen := map[uint]bool{}
	var order []AuditLogEntry
	page := first
	for {
		for _, e := range page.Data.Logs {
			require.False(t, seen[e.ID], "id %d returned twice", e.ID)
			seen[e.ID] = true
			order = append(order, e)
		}
		if page.Data.NextCursor == nil {
			break
		}
		code, page, _ = callAudit(t, h.GetAuditLogs, "/api/v1/audit/logs", url.Values{"page_size": {"10"}, "cursor": {*page.Data.NextCursor}})
		require.Equal(t, http.StatusOK, code)
		require.Nil(t, page.Data.Total, "a cursor page runs no count unless include_total")
	}
	require.Len(t, seen, 35)
	for i := 1; i < len(order); i++ {
		a, b := order[i-1], order[i]
		require.True(t, a.Timestamp.After(b.Timestamp) || (a.Timestamp.Equal(b.Timestamp) && a.ID > b.ID),
			"order broken at %d: %v/%d then %v/%d", i, a.Timestamp, a.ID, b.Timestamp, b.ID)
	}

	code, withTotal, _ := callAudit(t, h.GetAuditLogs, "/api/v1/audit/logs", url.Values{"page_size": {"10"}, "cursor": {*first.Data.NextCursor}, "include_total": {"true"}})
	require.Equal(t, http.StatusOK, code)
	require.EqualValues(t, 35, *withTotal.Data.Total)
}

func TestAuditLogs_OffsetCapAndBadCursorAre400(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditKeysetRows(t, db, 3, time.Now().UTC())
	h := NewAuditHandler(cs)

	code, _, _ := callAudit(t, h.GetAuditLogs, "/api/v1/audit/logs", url.Values{"page": {"100"}, "page_size": {"100"}})
	require.Equal(t, http.StatusOK, code, "the last page inside the cap")
	for _, page := range []string{"101", "99999999999999"} {
		code, env, _ := callAudit(t, h.GetAuditLogs, "/api/v1/audit/logs", url.Values{"page": {page}, "page_size": {"100"}})
		require.Equal(t, http.StatusBadRequest, code, "page %s", page)
		require.Contains(t, env.Message+env.Error, "cursor", "the refusal points to the cursor")
	}
	code, _, body := callAudit(t, h.GetAuditLogs, "/api/v1/audit/logs", url.Values{"cursor": {"not-a-cursor"}})
	require.Equal(t, http.StatusBadRequest, code)
	require.Contains(t, body, "invalid cursor")

	code, _, _ = callAudit(t, h.SearchAuditLogs, "/api/v1/audit/search", url.Values{"limit": {"1000"}, "offset": {"9000"}})
	require.Equal(t, http.StatusOK, code)
	code, env, _ := callAudit(t, h.SearchAuditLogs, "/api/v1/audit/search", url.Values{"limit": {"1000"}, "offset": {"9001"}})
	require.Equal(t, http.StatusBadRequest, code)
	require.Contains(t, env.Message+env.Error, "cursor")
	code, _, _ = callAudit(t, h.SearchAuditLogs, "/api/v1/audit/search", url.Values{"cursor": {"!!"}})
	require.Equal(t, http.StatusBadRequest, code)
}

func TestAuditSearch_CursorWalk(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditKeysetRows(t, db, 23, time.Now().UTC().Add(-time.Hour))
	h := NewAuditHandler(cs)
	q := url.Values{"limit": {"5"}, "action": {"secret.read"}}
	code, page, _ := callAudit(t, h.SearchAuditLogs, "/api/v1/audit/search", q)
	require.Equal(t, http.StatusOK, code)
	require.EqualValues(t, 23, *page.Data.Total)
	n := 0
	for {
		n += len(page.Data.Events)
		if page.Data.NextCursor == nil {
			break
		}
		q.Set("cursor", *page.Data.NextCursor)
		code, page, _ = callAudit(t, h.SearchAuditLogs, "/api/v1/audit/search", q)
		require.Equal(t, http.StatusOK, code)
	}
	require.Equal(t, 23, n)
}

// TestAuditExportCSV_StreamsAcrossBatches: a limit spanning several 500-row
// batches returns exactly limit rows, newest first, one header.
func TestAuditExportCSV_StreamsAcrossBatches(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	seedAuditKeysetRows(t, db, 1300, time.Now().UTC().Add(-2*time.Hour))
	h := NewAuditHandler(cs)
	code, _, body := callAudit(t, h.ExportAuditLogsCSV, "/api/v1/audit/export.csv", url.Values{"limit": {"1100"}})
	require.Equal(t, http.StatusOK, code)
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	require.NoError(t, err)
	require.Equal(t, "id", records[0][0])
	require.Len(t, records, 1+1100)

	var want []uint
	require.NoError(t, db.Model(&models.AuditEvent{}).Order("event_time DESC, id DESC").Limit(1100).Pluck("id", &want).Error)
	for i, rec := range records[1:] {
		id, err := strconv.ParseUint(rec[0], 10, 64)
		require.NoError(t, err)
		require.Equal(t, want[i], uint(id), "row %d", i)
	}
}

// TestAuditExportSIEM_SinceResolvesToAStartID: since returns exactly the rows
// at or after it, in id order, even when id order and time order disagree at
// the boundary (a later id stamped earlier).
func TestAuditExportSIEM_SinceResolvesToAStartID(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	at := func(sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }
	// ids 1..6, times out of id order around the since boundary (sec 10).
	for _, sec := range []int{1, 12, 9, 11, 10, 20} {
		require.NoError(t, db.Create(&models.AuditEvent{EventType: "secret.read", EventTime: at(sec)}).Error)
	}
	require.NoError(t, store.EnsureAuditListIndexesSQLite(db, t.Logf))
	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?since="+url.QueryEscape(at(10).Format(time.RFC3339)), nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var env struct {
		Data struct {
			Events []AuditExportEntry `json:"events"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	var got []string
	for _, e := range env.Data.Events {
		got = append(got, fmt.Sprintf("%d@%d", e.ID, int(e.Timestamp.Sub(base).Seconds())))
	}
	require.Equal(t, []string{"2@12", "4@11", "5@10", "6@20"}, got)
}
