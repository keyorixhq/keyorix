// audit_export_csv.go — ExportAuditLogsCSV: a CSV download of audit events for
// compliance hand-off and spreadsheets. Distinct from the JSON /audit/export (SIEM
// pull): this is a single bounded, human/auditor-friendly file with a header row.
package handlers

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// csvExportMaxRows bounds a single CSV download.
const csvExportMaxRows = 10000

// ExportAuditLogsCSV handles GET /api/v1/audit/export.csv — newest-first audit events
// as a CSV attachment. Gated by audit.read (the /audit group). Filters: ?project_id,
// ?user_id, ?since / ?until (RFC3339), ?limit (default 1000, cap csvExportMaxRows).
func (h *AuditHandler) ExportAuditLogsCSV(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	limit := 1000
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= csvExportMaxRows {
		limit = l
	}
	filter := &storage.AuditFilter{PageSize: limit}
	if v := r.URL.Query().Get("project_id"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			p := uint(n)
			filter.ProjectID = &p
		}
	}
	if v := r.URL.Query().Get("user_id"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			u := uint(n)
			filter.UserID = &u
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.StartTime = &t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.EndTime = &t
		}
	}

	events, _, err := h.coreService.Storage().GetAuditLogs(r.Context(), filter)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to export audit logs", http.StatusInternalServerError, nil)
		return
	}
	actorNames := h.coreService.ResolveUsernames(r.Context(), events)
	name := func(id *uint) string {
		if id == nil {
			return ""
		}
		return actorNames[*id]
	}
	uintStr := func(id *uint) string {
		if id == nil {
			return ""
		}
		return strconv.FormatUint(uint64(*id), 10)
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"id", "event_time", "event_type", "actor", "actor_type",
		"user_id", "project_id", "secret_id", "ip_address", "success", "description",
	})
	for _, e := range events {
		success := "true"
		if e.Success != nil && !*e.Success {
			success = "false"
		}
		_ = cw.Write([]string{
			strconv.FormatUint(uint64(e.ID), 10),
			e.EventTime.UTC().Format(time.RFC3339),
			e.EventType,
			name(e.UserID),
			actorTypeOrDefault(e.ActorType),
			uintStr(e.UserID),
			uintStr(e.ProjectID),
			uintStr(e.SecretNodeID),
			e.IPAddress,
			success,
			e.Description,
		})
	}
}
