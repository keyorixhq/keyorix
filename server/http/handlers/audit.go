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
	ID        uint   `json:"id"`
	EventType string `json:"event_type"`
	Actor     string `json:"actor"`
	// ActorType is the acting-principal kind: "user" or "machine_identity"
	// (also "system"). Lets the audit view segment/filter human vs machine
	// activity (ADR-023).
	ActorType   string    `json:"actor_type"`
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
	if at := r.URL.Query().Get("actor_type"); validActorType(at) {
		filter.ActorType = &at
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
			ActorType:   actorTypeOrDefault(e.ActorType),
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

// AuditExportEntry is the full-fidelity wire shape for SIEM ingestion. Unlike
// AuditLogEntry (UI-oriented) it preserves the raw IDs, success flag, diff, and
// impersonation attribution so an external system can index every field.
type AuditExportEntry struct {
	ID             uint            `json:"id"`
	EventType      string          `json:"event_type"`
	Timestamp      time.Time       `json:"timestamp"`
	Actor          string          `json:"actor"`
	UserID         *uint           `json:"user_id,omitempty"`
	ProjectID      *uint           `json:"project_id,omitempty"`
	SecretID       *uint           `json:"secret_id,omitempty"`
	Description    string          `json:"description"`
	IPAddress      string          `json:"ip_address,omitempty"`
	ActorType      string          `json:"actor_type"`
	Success        bool            `json:"success"`
	Diff           json.RawMessage `json:"diff,omitempty"`
	Impersonation  bool            `json:"impersonation,omitempty"`
	ImpersonatedBy string          `json:"impersonated_by,omitempty"`
	ActingAs       string          `json:"acting_as,omitempty"`
	// PrevHash/EntryHash are the ADR-029 chain links. Exporting them gives the SIEM
	// (the off-box observer) the anchor needed to detect on-box tampering —
	// including tail-truncation, which on-box re-verification cannot catch.
	PrevHash  string `json:"prev_hash,omitempty"`
	EntryHash string `json:"entry_hash,omitempty"`
}

// ExportAuditLogs handles GET /api/v1/audit/export — a cursor-paginated,
// full-fidelity audit feed for SIEM pull. Authenticated as a normal API caller
// (a SIEM uses a personal access token) and gated by audit.read. Advance the
// cursor by passing the last returned id as ?after_id= on the next request;
// next_cursor in the response is the id to use, or null when caught up.
func (h *AuditHandler) ExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	limit := 100
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 1000 {
		limit = l
	}
	filter := &storage.AuditFilter{Ascending: true, PageSize: limit}
	if aidStr := r.URL.Query().Get("after_id"); aidStr != "" {
		if aid, err := strconv.ParseUint(aidStr, 10, 32); err == nil {
			a := uint(aid)
			filter.AfterID = &a
		}
	}
	if st := r.URL.Query().Get("since"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			filter.StartTime = &t
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

	entries := make([]AuditExportEntry, 0, len(events))
	var nextCursor *uint
	for _, e := range events {
		success := true
		if e.Success != nil {
			success = *e.Success
		}
		entry := AuditExportEntry{
			ID:          e.ID,
			EventType:   e.EventType,
			Timestamp:   e.EventTime,
			Actor:       name(e.UserID),
			UserID:      e.UserID,
			ProjectID:   e.ProjectID,
			SecretID:    e.SecretNodeID,
			Description: e.Description,
			IPAddress:   e.IPAddress,
			ActorType:   actorTypeOrDefault(e.ActorType),
			Success:     success,
			PrevHash:    e.PrevHash,
			EntryHash:   e.EntryHash,
		}
		if e.Diff != "" {
			entry.Diff = json.RawMessage(e.Diff)
		}
		if e.Impersonation {
			entry.Impersonation = true
			entry.ImpersonatedBy = name(e.ImpersonatedBy)
			entry.ActingAs = name(e.ActingAs)
		}
		entries = append(entries, entry)
		id := e.ID
		nextCursor = &id
	}

	sendSuccess(w, map[string]interface{}{
		"events":      entries,
		"count":       len(entries),
		"next_cursor": nextCursor,
	}, "")
}

// validActorType reports whether s is an audit actor-type filter value.
func validActorType(s string) bool {
	switch s {
	case core.ActorTypeUser, core.ActorTypeMachine, core.ActorTypeSystem:
		return true
	default:
		return false
	}
}

// actorTypeOrDefault normalizes a stored actor_type, treating an empty value
// (legacy rows written before the column existed) as a human user.
func actorTypeOrDefault(s string) string {
	if s == "" {
		return core.ActorTypeUser
	}
	return s
}

// GetRBACAuditLogs handles GET /api/v1/audit/rbac-logs — the role-assignment
// audit trail (role.assigned / role.removed).
func (h *AuditHandler) GetRBACAuditLogs(w http.ResponseWriter, r *http.Request) {
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

	entries, total, err := h.coreService.ListRBACAuditLogs(r.Context(), page, pageSize)
	if err != nil {
		sendError(w, "InternalError", "Failed to retrieve RBAC audit logs", http.StatusInternalServerError, nil)
		return
	}

	logs := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		logs = append(logs, map[string]interface{}{
			"id":             e.ID,
			"action":         e.Action,
			"actor_user_id":  e.ActorUserID,
			"target_user_id": e.TargetUserID,
			"group_id":       e.GroupID,
			"role_id":        e.RoleID,
			"permission_id":  e.PermissionID,
			"project_id":     e.ProjectID,
			"details":        e.Details,
			"created_at":     e.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	totalPages := 0
	if pageSize > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	sendSuccess(w, map[string]interface{}{
		"logs": logs, "page": page, "page_size": pageSize, "total": total, "total_pages": totalPages,
	}, "")
}

// GetAuditRetention handles GET /api/v1/audit/retention — reports how far back
// the audit trail demonstrably reaches (total events, oldest/newest event,
// coverage days, and whether that covers the NIS2-mandated 12 months). Keyorix
// never purges audit events, so this makes the unlimited-retention claim
// auditable rather than merely asserted.
func (h *AuditHandler) GetAuditRetention(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	cov, err := h.coreService.AuditRetentionCoverage(r.Context())
	if err != nil {
		sendError(w, "InternalError", "Failed to compute audit retention coverage", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, cov, "")
}

// VerifyAuditChain handles GET /api/v1/audit/verify — re-walks the
// tamper-evidence hash chain (ADR-029) and reports whether the audit trail is
// intact, naming the first divergent event on failure.
func (h *AuditHandler) VerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	v, err := h.coreService.VerifyAuditChain(r.Context())
	if err != nil {
		sendError(w, "InternalError", "Failed to verify audit chain", http.StatusInternalServerError, nil)
		return
	}

	resp := map[string]interface{}{
		"valid":            v.Valid,
		"chained_events":   v.ChainedEvents,
		"unchained_events": v.UnchainedEvents,
		// The verified chain head — record (chained_events, head_hash) externally to
		// detect tail-truncation / re-seed that an on-box re-walk can't catch alone.
		"head_hash": v.HeadHash,
		"head_id":   v.HeadID,
		// checkpointed=true when the chain was also verified against a signed in-DB
		// checkpoint (ADR-029) — on-box truncation detection a DBA cannot forge.
		"checkpointed": v.Checkpointed,
	}
	if !v.Valid {
		resp["first_broken_id"] = v.FirstBrokenID
		resp["reason"] = v.Reason
	}
	if v.CheckpointReason != "" {
		resp["checkpoint_reason"] = v.CheckpointReason
	}
	sendSuccess(w, resp, "")
}

// WriteAuditCheckpoint handles POST /api/v1/audit/checkpoint — signs a checkpoint
// of the current verified audit-chain head (ADR-029) on demand. The usual source
// of checkpoints is the background scheduler; this lets an operator re-baseline
// immediately — e.g. right after a DEK rotation, when verify fails closed until a
// fresh checkpoint is written under the new key. Privileged (system.write, on top
// of the audit group's audit.read).
func (h *AuditHandler) WriteAuditCheckpoint(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	cp, written, err := h.coreService.WriteAuditCheckpoint(r.Context())
	if err != nil {
		// The chain did not verify (broken, or a prior signed checkpoint proves a
		// truncation) — the server refuses to notarise it. Surface the reason so the
		// operator can investigate; it is a precondition failure, not a server error.
		sendError(w, "Conflict", err.Error(), http.StatusConflict, nil)
		return
	}
	if !written {
		sendError(w, "PreconditionFailed",
			"signed audit checkpoints require encryption to be enabled (the signing key is derived from the DEK)",
			http.StatusPreconditionFailed, nil)
		return
	}

	resp := map[string]interface{}{
		"id":             cp.ID,
		"chained_events": cp.ChainedEvents,
		"head_id":        cp.HeadID,
		"head_hash":      cp.HeadHash,
		"key_version":    cp.KeyVersion,
	}
	// Surface the external-notary anchor when one was obtained (ADR-029).
	if cp.AnchoredAt != nil {
		resp["anchored_at"] = cp.AnchoredAt.UTC()
		resp["anchor_provider"] = cp.AnchorProvider
	}
	sendSuccess(w, resp, "audit checkpoint written")
}
