// machine_identities.go — machine identity endpoints (ADR-023).
//
// Non-human project members, segmented from human members in the Members view.
// Project-scoped: list is users.read; create/transition need roles.assign.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListMachineIdentities handles GET /api/v1/projects/{id}/machine-identities.
func (h *CatalogHandler) ListMachineIdentities(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	identities, err := h.coreService.ListMachineIdentities(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"machine_identities": identities}, "")
}

// CreateMachineIdentity handles POST /api/v1/projects/{id}/machine-identities.
func (h *CatalogHandler) CreateMachineIdentity(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name         string `json:"name"`
		IdentityType string `json:"identity_type"`
		Description  string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Name == "" {
		sendError(w, "ValidationError", "name is required", http.StatusBadRequest, nil)
		return
	}
	m, err := h.coreService.CreateMachineIdentity(r.Context(), uint(id), body.Name, body.IdentityType, body.Description, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "invalid identity_type") || strings.Contains(err.Error(), "required") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"machine_identity": m}, "Machine identity created")
}

// TransitionMachineIdentity handles PUT /api/v1/projects/{id}/machine-identities/{machineId}.
// Body: {"action": "activate" | "suspend" | "revoke"}.
func (h *CatalogHandler) TransitionMachineIdentity(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid machine identity ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	to, ok := machineActionState(body.Action)
	if !ok {
		sendError(w, "ValidationError", "action must be activate, suspend, or revoke", http.StatusBadRequest, nil)
		return
	}
	m, err := h.coreService.TransitionMachineIdentity(r.Context(), uint(projectID), uint(machineID), to, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "cannot transition"):
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"machine_identity": m}, "Machine identity updated")
}

// IssueMachineToken handles POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens.
// Returns the raw token ONCE. Body: {"name": "...", "expires_in_days": 90}.
func (h *CatalogHandler) IssueMachineToken(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid machine identity ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name          string `json:"name"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	var expiresAt *time.Time
	if body.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, body.ExpiresInDays)
		expiresAt = &t
	}
	result, err := h.coreService.IssueMachineToken(r.Context(), uint(projectID), uint(machineID), body.Name, expiresAt, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "must be active"):
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{
		"token":      result.PlainToken, // shown once
		"id":         result.Credential.ID,
		"prefix":     result.Credential.TokenPrefix,
		"expires_at": result.Credential.ExpiresAt,
	}, "Machine token issued — copy it now; it will not be shown again")
}

// ListMachineTokens handles GET /api/v1/projects/{id}/machine-identities/{machineId}/tokens.
// Returns credential metadata only — never the token.
func (h *CatalogHandler) ListMachineTokens(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid machine identity ID", http.StatusBadRequest, nil)
		return
	}
	creds, err := h.coreService.ListMachineTokens(r.Context(), uint(projectID), uint(machineID))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]interface{}, 0, len(creds))
	for _, c := range creds {
		out = append(out, map[string]interface{}{
			"id":           c.ID,
			"name":         c.Name,
			"prefix":       c.TokenPrefix,
			"last_used_at": c.LastUsedAt,
			"expires_at":   c.ExpiresAt,
			"revoked":      c.Revoked,
			"created_at":   c.CreatedAt,
		})
	}
	sendSuccess(w, map[string]interface{}{"tokens": out}, "")
}

// RevokeMachineToken handles DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}.
func (h *CatalogHandler) RevokeMachineToken(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid machine identity ID", http.StatusBadRequest, nil)
		return
	}
	tokenID, err := strconv.ParseUint(chi.URLParam(r, "tokenId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid token ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	if err := h.coreService.RevokeMachineToken(r.Context(), uint(projectID), uint(machineID), uint(tokenID), actor.UserID); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Machine token revoked")
}

// GrantMachineRole handles POST /api/v1/projects/{id}/machine-identities/{machineId}/roles.
// Body: {"role_id": 5}. The role is granted at the project scope.
func (h *CatalogHandler) GrantMachineRole(w http.ResponseWriter, r *http.Request) {
	h.changeMachineRole(w, r, true)
}

// RemoveMachineRole handles DELETE /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}.
func (h *CatalogHandler) RemoveMachineRole(w http.ResponseWriter, r *http.Request) {
	h.changeMachineRole(w, r, false)
}

func (h *CatalogHandler) changeMachineRole(w http.ResponseWriter, r *http.Request, grant bool) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid machine identity ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var roleID uint
	if grant {
		var body struct {
			RoleID uint `json:"role_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RoleID == 0 {
			sendError(w, "ValidationError", "role_id is required", http.StatusBadRequest, nil)
			return
		}
		roleID = body.RoleID
	} else {
		rid, err := strconv.ParseUint(chi.URLParam(r, "roleId"), 10, 32)
		if err != nil {
			sendError(w, "InvalidParameter", "Invalid role ID", http.StatusBadRequest, nil)
			return
		}
		roleID = uint(rid)
	}

	scope := core.Scope{ProjectID: uint(projectID)}
	if grant {
		err = h.coreService.AssignMachineRole(r.Context(), uint(machineID), roleID, scope, actor.UserID)
	} else {
		err = h.coreService.RemoveMachineRole(r.Context(), uint(machineID), roleID, scope, actor.UserID)
	}
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "already") || strings.Contains(err.Error(), "not assigned"):
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	verb := "granted"
	if !grant {
		verb = "removed"
	}
	sendSuccess(w, nil, "Machine role "+verb)
}

// CreateOIDCBinding handles POST /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings.
// Body: {"issuer": "...", "subject": "..."} (ADR-031).
func (h *CatalogHandler) CreateOIDCBinding(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, actor, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	var body struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	b, err := h.coreService.CreateOIDCBinding(r.Context(), projectID, machineID, body.Issuer, body.Subject, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "required"):
			status = http.StatusBadRequest
		case strings.Contains(err.Error(), "already bound"):
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"id": b.ID, "issuer": b.Issuer, "subject": b.Subject}, "OIDC binding created")
}

// ListOIDCBindings handles GET /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings.
func (h *CatalogHandler) ListOIDCBindings(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, _, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	bindings, err := h.coreService.ListOIDCBindings(r.Context(), projectID, machineID)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	out := make([]map[string]interface{}, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, map[string]interface{}{"id": b.ID, "issuer": b.Issuer, "subject": b.Subject, "created_at": b.CreatedAt})
	}
	sendSuccess(w, map[string]interface{}{"bindings": out}, "")
}

// DeleteOIDCBinding handles DELETE /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}.
func (h *CatalogHandler) DeleteOIDCBinding(w http.ResponseWriter, r *http.Request) {
	projectID, machineID, actor, ok := h.machineRouteCtx(w, r)
	if !ok {
		return
	}
	bindingID, err := strconv.ParseUint(chi.URLParam(r, "bindingId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid binding ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteOIDCBinding(r.Context(), projectID, machineID, uint(bindingID), actor.UserID); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "OIDC binding removed")
}

// machineRouteCtx parses the project + machine path params and the actor,
// writing the appropriate error response and returning ok=false on failure.
func (h *CatalogHandler) machineRouteCtx(w http.ResponseWriter, r *http.Request) (projectID, machineID uint, actor *middleware.UserContext, ok bool) {
	pid, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	mid, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid machine identity ID", http.StatusBadRequest, nil)
		return
	}
	actor = middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	return uint(pid), uint(mid), actor, true
}

func machineActionState(action string) (string, bool) {
	switch action {
	case "activate":
		return core.MachineActive, true
	case "suspend":
		return core.MachineSuspended, true
	case "revoke":
		return core.MachineRevoked, true
	default:
		return "", false
	}
}
