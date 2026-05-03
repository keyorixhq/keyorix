// shares_query.go — List and status query handlers.
//
// ListSecretShares, ListShares, ListSharedSecrets,
// GetSharingStatusWithIndicators, RemoveSelfFromShare.
// For share create/update/revoke see shares_crud.go.
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSecretShares handles GET /api/v1/secrets/{id}/shares
func (h *ShareHandler) ListSecretShares(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	shares, err := h.coreService.ListSecretShares(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing secret shares: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to list secret shares", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, map[string]interface{}{"shares": shares}, "")
}

// ListShares handles GET /api/v1/shares
func (h *ShareHandler) ListShares(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	shares, err := h.coreService.ListSharesByUser(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing shares: %v", err)
		h.sendError(w, "InternalError", "Failed to list shares", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, map[string]interface{}{"shares": shares}, "")
}

// ListSharedSecrets handles GET /api/v1/shared-secrets
func (h *ShareHandler) ListSharedSecrets(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	secrets, err := h.coreService.ListSharedSecrets(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing shared secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list shared secrets", http.StatusInternalServerError, nil)
		return
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}

	h.sendSuccess(w, map[string]interface{}{"secrets": secrets}, "")
}

// GetSharingStatusWithIndicators handles GET /api/v1/secrets/{id}/sharing-status
func (h *ShareHandler) GetSharingStatusWithIndicators(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	status, err := h.coreService.GetSecretSharingStatusWithIndicators(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error getting sharing status: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get sharing status", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, status, "")
}

// RemoveSelfFromShare handles DELETE /api/v1/secrets/{id}/self-share
func (h *ShareHandler) RemoveSelfFromShare(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.RemoveSelfFromShare(r.Context(), uint(id), userCtx.UserID); err != nil {
		log.Printf("Error removing self from share: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Share not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to remove self from share", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
