// sod.go — separation-of-duties endpoints (ISO 27001 A.5.3 / SOX). Deployment-wide:
// listing policy DEFINITIONS (name/permission pair, no PII) needs only the universal
// system_viewer baseline system.read; listing VIOLATIONS discloses violator
// names/emails deployment-wide, so it needs audit.read; creating/deleting policies
// needs system.write (wired in router.go).
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSoDPolicies handles GET /api/v1/sod/policies.
func (h *CatalogHandler) ListSoDPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.coreService.ListSoDPolicies(r.Context())
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"policies": policies, "count": len(policies)}, "")
}

// CreateSoDPolicy handles POST /api/v1/sod/policies.
func (h *CatalogHandler) CreateSoDPolicy(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		PermissionA string `json:"permission_a"`
		PermissionB string `json:"permission_b"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	policy, err := h.coreService.CreateSoDPolicy(r.Context(), actor.UserID, body.Name, body.Description, body.PermissionA, body.PermissionB)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "must be different") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"policy": policy}, "Policy created")
}

// DeleteSoDPolicy handles DELETE /api/v1/sod/policies/{id}.
func (h *CatalogHandler) DeleteSoDPolicy(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid policy ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteSoDPolicy(r.Context(), actor.UserID, uint(id)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Policy deleted")
}

// ListSoDViolations handles GET /api/v1/sod/violations.
func (h *CatalogHandler) ListSoDViolations(w http.ResponseWriter, r *http.Request) {
	violations, err := h.coreService.DetectSoDViolations(r.Context())
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"violations": violations, "count": len(violations)}, "")
}
