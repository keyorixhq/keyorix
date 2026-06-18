// secrets_deleted.go — DeletedSecrets handler: the recycle bin, a project's
// soft-deleted (restorable) secrets.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// deletedSecretEntry is the wire format for one trashed secret. Metadata only — no
// value, ever.
type deletedSecretEntry struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Classification string `json:"classification,omitempty"`
	EnvironmentID  uint   `json:"environment_id"`
	OwnerID        uint   `json:"owner_id"`
	DeletedAt      string `json:"deleted_at,omitempty"`
}

// DeletedSecrets handles GET /api/v1/projects/{id}/secrets/deleted?limit=N — the
// project's recycle bin (soft-deleted secrets, most-recently-deleted first), so an
// operator can find a secret's ID to POST /secrets/{id}/restore. Scoped secrets.read
// (project) is enforced by the router. limit defaults to 100, capped at 500.
func (h *SecretHandler) DeletedSecrets(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}

	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil {
			limit = n
		}
	}

	secrets, err := h.coreService.ListDeletedSecrets(r.Context(), uint(id), limit)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to list deleted secrets", http.StatusInternalServerError, nil)
		return
	}

	entries := make([]deletedSecretEntry, 0, len(secrets))
	for _, s := range secrets {
		entries = append(entries, toDeletedSecretEntry(s))
	}
	h.sendSuccess(w, map[string]interface{}{"deleted": entries, "total": len(entries)}, "")
}

func toDeletedSecretEntry(s *models.SecretNode) deletedSecretEntry {
	e := deletedSecretEntry{
		ID:             s.ID,
		Name:           s.Name,
		Type:           s.Type,
		Classification: s.Classification,
		EnvironmentID:  s.EnvironmentID,
		OwnerID:        s.OwnerID,
	}
	if s.DeletedAt.Valid {
		e.DeletedAt = s.DeletedAt.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return e
}
