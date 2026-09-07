// admin_usage.go — GET /api/v1/admin/usage handler.
//
// Returns a per-project usage report (secret counts + read activity) for the
// requested time window, for every project or one named via ?project_id=, with
// no ownership check anywhere in the call chain (core.GetUsageReport ->
// storage.GetProjectUsageStats). Gated by audit.read in the router. Do not gate
// this — or any new caller — on system.read: that permission is granted to
// every user via the baseline system_viewer role (CreateUser, SSO/JIT and SCIM
// provisioning all assign it), so it is equivalent to no gate at all for this
// disclosure-sensitive, deployment-wide report. Gating on system.read was a
// real, fixed vulnerability, same family as CP-001/CP-008; see
// server/http/deployment_disclosure_family_test.go.
package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
)

// AdminUsageHandler serves GET /api/v1/admin/usage.
type AdminUsageHandler struct {
	coreService *core.KeyorixCore
}

// NewAdminUsageHandler constructs an AdminUsageHandler.
func NewAdminUsageHandler(cs *core.KeyorixCore) *AdminUsageHandler {
	return &AdminUsageHandler{coreService: cs}
}

// GetUsageReport handles GET /api/v1/admin/usage.
//
// Query params:
//
//	days       int   reporting window in days (1-365, default 30)
//	project_id uint  scope to one project (omit for all projects)
func (h *AdminUsageHandler) GetUsageReport(w http.ResponseWriter, r *http.Request) {
	// Parse days param (default 30, max 365)
	days := 30
	if s := r.URL.Query().Get("days"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}

	// Parse optional project_id param
	var projectID *uint
	if s := r.URL.Query().Get("project_id"); s != "" {
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			id := uint(n)
			projectID = &id
		}
	}

	report, err := h.coreService.GetUsageReport(r.Context(), days, projectID)
	if err != nil {
		log.Printf("GetUsageReport: %v", err)
		sendError(w, "InternalError", "Failed to generate usage report", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, report, "")
}
