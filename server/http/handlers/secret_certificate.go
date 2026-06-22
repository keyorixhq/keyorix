// secret_certificate.go — certificate inspection handler (ADR-054).
//
// Route (under /api/v1/secrets, project-scoped from the {id} secret):
//
//	GET /{id}/certificate — public X.509 metadata of a certificate-valued secret
package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSecretCertificate handles GET /api/v1/secrets/{id}/certificate
func (h *SecretHandler) GetSecretCertificate(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}
	info, err := h.coreService.InspectCertificate(r.Context(), userCtx.UserID, uint(id))
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "not a parseable"), strings.Contains(msg, "suspended"):
			status = http.StatusBadRequest
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, info, "")
}
