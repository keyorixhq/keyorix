// secrets_inventory_csv.go — SecretsInventoryCSV handler: a CSV asset-inventory
// manifest of a project's secrets (metadata only, never values) for compliance
// hand-off (ISO 27001 A.5.9). Scoped secrets.read (project) is enforced by the router.
package handlers

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SecretsInventoryCSV handles GET /api/v1/projects/{id}/secrets/inventory.csv — every
// live secret in the project as a CSV attachment (id, name, environment, type,
// classification, owner, created, expiration, last-rotated). No secret values.
func (h *SecretHandler) SecretsInventoryCSV(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}

	items, err := h.coreService.SecretsInventory(r.Context(), uint(id))
	if err != nil {
		h.sendError(w, "InternalError", "Failed to build secret inventory", http.StatusInternalServerError, nil)
		return
	}

	tstr := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="secret-inventory.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"id", "name", "environment", "type", "classification",
		"owner", "created_at", "expiration", "last_rotated_at",
	})
	for _, it := range items {
		_ = cw.Write([]string{
			strconv.FormatUint(uint64(it.ID), 10),
			it.Name,
			it.EnvironmentName,
			it.Type,
			it.Classification,
			it.OwnerUsername,
			it.CreatedAt.UTC().Format(time.RFC3339),
			tstr(it.Expiration),
			tstr(it.LastRotatedAt),
		})
	}
}
