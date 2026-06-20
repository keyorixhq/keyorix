// secrets_inventory_deployment_csv.go — DeploymentSecretsInventoryCSV handler: the
// org-wide secret asset inventory (every project's secrets, metadata only, never
// values) as a CSV attachment for compliance. Deployment-wide system.read is enforced
// by the router. Parallels the per-project secrets_inventory_csv handler.
package handlers

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// DeploymentSecretsInventoryCSV handles GET /api/v1/secrets/inventory.csv — every live
// secret across all projects as a CSV attachment (project, id, name, environment, type,
// classification, owner, created, expiration, last-rotated). No secret values.
func (h *SecretHandler) DeploymentSecretsInventoryCSV(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	items, err := h.coreService.DeploymentSecretsInventory(r.Context())
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
	w.Header().Set("Content-Disposition", `attachment; filename="secret-inventory-all-projects.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"project", "id", "name", "environment", "type", "classification",
		"owner", "created_at", "expiration", "last_rotated_at",
	})
	for _, it := range items {
		_ = cw.Write([]string{
			it.ProjectName,
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
