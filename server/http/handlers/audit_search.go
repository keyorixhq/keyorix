// audit_search.go — SearchAuditLogs HTTP handler.
//
// GET /api/v1/audit/search exposes the richer AuditSearchRequest filters
// (actor username partial match, IP address, resource type, success flag,
// RFC3339 time range, limit/offset) on top of the existing GET /audit/logs
// endpoint. It shares the same audit.read permission gate.
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// parseAuditSearchRequest extracts and coerces all query-string parameters for the
// audit search endpoint into a core.AuditSearchRequest.
func parseAuditSearchRequest(r *http.Request) core.AuditSearchRequest {
	q := r.URL.Query()
	req := core.AuditSearchRequest{}

	if v := q.Get("actor"); v != "" {
		req.ActorUsername = v
	}
	if v := q.Get("user_id"); v != "" {
		if uid, err := strconv.ParseUint(v, 10, 32); err == nil {
			req.UserID = uint(uid)
		}
	}
	if v := q.Get("project_id"); v != "" {
		if pid, err := strconv.ParseUint(v, 10, 32); err == nil {
			req.ProjectID = uint(pid)
		}
	}
	if v := q.Get("action"); v != "" {
		req.Action = v
	}
	if v := q.Get("resource_type"); v != "" {
		req.ResourceType = v
	}
	if v := q.Get("resource_id"); v != "" {
		if rid, err := strconv.ParseUint(v, 10, 32); err == nil {
			req.ResourceID = uint(rid)
		}
	}
	if v := q.Get("ip"); v != "" {
		req.IPAddress = v
	}
	if v := q.Get("success"); v != "" {
		switch v {
		case "true":
			t := true
			req.Success = &t
		case "false":
			f := false
			req.Success = &f
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			req.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			req.Until = t
		}
	}
	if v := q.Get("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil {
			req.Limit = l
		}
	}
	if v := q.Get("offset"); v != "" {
		if o, err := strconv.Atoi(v); err == nil && o >= 0 {
			req.Offset = o
		}
	}
	return req
}

// SearchAuditLogs handles GET /api/v1/audit/search.
//
// Supported query parameters:
//
//	actor        — partial username match
//	user_id      — exact numeric user ID
//	project_id   — exact numeric project ID
//	action       — exact event_type (e.g. secret.read)
//	resource_type — resource kind prefix (e.g. "secret")
//	resource_id  — exact secret_node_id
//	ip           — exact originating IP address
//	success      — "true" or "false"
//	since        — RFC3339 start of time range (inclusive)
//	until        — RFC3339 end of time range (inclusive)
//	limit        — max results (1–1000, default 100)
//	offset       — pagination offset (default 0)
func (h *AuditHandler) SearchAuditLogs(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	req := parseAuditSearchRequest(r)

	result, err := h.coreService.SearchAuditLogs(r.Context(), req)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to search audit logs", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"events": result.Events,
		"total":  result.Total,
	}, "")
}
