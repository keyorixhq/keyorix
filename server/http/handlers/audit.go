// audit.go — GetAuditLogs, GetRBACAuditLogs, and audit log types.
//
// For anomaly alert handlers see audit_anomaly.go.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// AuditHandler handles audit log HTTP requests.
type AuditHandler struct {
	coreService *core.KeyorixCore
}

// NewAuditHandler constructs an AuditHandler.
func NewAuditHandler(coreService *core.KeyorixCore) *AuditHandler {
	return &AuditHandler{coreService: coreService}
}

// AuditLogEntry is the wire format returned to the frontend.
type AuditLogEntry struct {
	ID          uint      `json:"id"`
	EventType   string    `json:"event_type"`
	Actor       string    `json:"actor"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	// Diff is the structured before/after payload for mutation events (parsed
	// from the stored JSON), omitted when absent. Never contains plaintext values.
	Diff json.RawMessage `json:"diff,omitempty"`
	// Impersonation attribution — present on impersonated events. Actors are
	// resolved to human-readable usernames, not opaque IDs.
	Impersonation  bool   `json:"impersonation,omitempty"`
	ImpersonatedBy string `json:"impersonated_by,omitempty"`
	ActingAs       string `json:"acting_as,omitempty"`
}

// GetAuditLogs handles GET /api/v1/audit/logs
func (h *AuditHandler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	page, pageSize := 1, 50
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}

	filter := &storage.AuditFilter{Page: page, PageSize: pageSize}

	if action := r.URL.Query().Get("action"); action != "" {
		filter.Action = &action
	}
	if uidStr := r.URL.Query().Get("user_id"); uidStr != "" {
		if uid, err := strconv.ParseUint(uidStr, 10, 32); err == nil {
			u := uint(uid)
			filter.UserID = &u
		}
	}
	if pidStr := r.URL.Query().Get("project_id"); pidStr != "" {
		if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			p := uint(pid)
			filter.ProjectID = &p
		}
	}
	if st := r.URL.Query().Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			filter.StartTime = &t
		}
	}
	if et := r.URL.Query().Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			filter.EndTime = &t
		}
	}

	events, total, err := h.coreService.Storage().GetAuditLogs(r.Context(), filter)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to fetch audit logs", http.StatusInternalServerError, nil)
		return
	}

	// Resolve actor usernames in bulk.
	actorNames := h.coreService.ResolveUsernames(r.Context(), events)

	entries := make([]AuditLogEntry, 0, len(events))
	for _, e := range events {
		var uid uint
		if e.UserID != nil {
			uid = *e.UserID
		}
		actor := actorNames[uid]
		entry := AuditLogEntry{
			ID:          e.ID,
			EventType:   e.EventType,
			Actor:       actor,
			Description: e.Description,
			Timestamp:   e.EventTime,
		}
		if e.Diff != "" {
			entry.Diff = json.RawMessage(e.Diff)
		}
		if e.Impersonation {
			entry.Impersonation = true
			if e.ImpersonatedBy != nil {
				entry.ImpersonatedBy = actorNames[*e.ImpersonatedBy]
			}
			if e.ActingAs != nil {
				entry.ActingAs = actorNames[*e.ActingAs]
			}
		}
		entries = append(entries, entry)
	}

	totalPages := int(total)/pageSize + 1
	if int(total)%pageSize == 0 && total > 0 {
		totalPages = int(total) / pageSize
	}

	sendSuccess(w, map[string]interface{}{
		"logs":        entries,
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": totalPages,
	}, "")
}

// GetRBACAuditLogs handles GET /api/v1/audit/rbac-logs (stub — returns empty).
func (h *AuditHandler) GetRBACAuditLogs(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"logs": []interface{}{}, "page": 1, "page_size": 50, "total": 0, "total_pages": 0,
	}, "")
}
