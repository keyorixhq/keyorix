// permission_baseline.go — HTTP handlers for the permission baseline attestation
// endpoints. Two routes:
//
//	GET /api/v1/compliance/permission-baseline       → JSON PermissionBaseline
//	GET /api/v1/compliance/permission-baseline.csv   → CSV attachment
//
// Both require the audit.read permission (same gate as the other compliance
// endpoints in this family). The handler lives on DashboardHandler so it has no
// new struct to register in the router.
package handlers

import (
	"encoding/csv"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetPermissionBaseline handles GET /api/v1/compliance/permission-baseline.
// Returns the full user→role→permission edge list as JSON.
func (h *DashboardHandler) GetPermissionBaseline(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	baseline, err := h.coreService.GetPermissionBaseline(r.Context())
	if err != nil {
		sendError(w, "InternalError", "Failed to generate permission baseline", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, baseline, "")
}

// GetPermissionBaselineCSV handles GET /api/v1/compliance/permission-baseline.csv.
// Returns the same data as a CSV attachment suitable for auditor hand-off.
func (h *DashboardHandler) GetPermissionBaselineCSV(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	baseline, err := h.coreService.GetPermissionBaseline(r.Context())
	if err != nil {
		sendError(w, "InternalError", "Failed to generate permission baseline", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="permission-baseline.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	_ = cw.Write([]string{"user_id", "username", "email", "role_name", "scope", "permission", "grant_expired", "holder_deleted"})
	for _, row := range baseline.Rows {
		_ = cw.Write([]string{
			strconv.FormatUint(uint64(row.UserID), 10),
			csvSafe(row.Username),
			csvSafe(row.Email),
			csvSafe(row.RoleName),
			csvSafe(row.Scope),
			csvSafe(row.Permission),
			strconv.FormatBool(row.GrantExpired),
			strconv.FormatBool(row.HolderDeleted),
		})
	}
}
