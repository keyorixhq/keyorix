// machine_audit.go — machine identity audit report endpoints.
//
// GET /api/v1/machine-identities/audit      → JSON MachineAuditReport
// GET /api/v1/machine-identities/audit.csv  → CSV of the same data
//
// Both require the global audit.read permission (same calibration as
// /pat-hygiene and /machine-token-hygiene).
package handlers

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// MachineAuditHandler serves the machine identity audit report.
type MachineAuditHandler struct {
	coreService *core.KeyorixCore
}

// NewMachineAuditHandler constructs a MachineAuditHandler.
func NewMachineAuditHandler(coreService *core.KeyorixCore) *MachineAuditHandler {
	return &MachineAuditHandler{coreService: coreService}
}

// GetMachineAuditReport handles GET /api/v1/machine-identities/audit.
// Returns the full audit report as JSON.
func (h *MachineAuditHandler) GetMachineAuditReport(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	report, err := h.coreService.GetMachineAuditReport(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to generate machine audit report", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, report, "")
}

// GetMachineAuditReportCSV handles GET /api/v1/machine-identities/audit.csv.
// Returns the audit report as a CSV attachment.
func (h *MachineAuditHandler) GetMachineAuditReportCSV(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	report, err := h.coreService.GetMachineAuditReport(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to generate machine audit report", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="machine-audit.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"machine_id", "name", "description",
		"credential_count", "last_used_at",
		"is_stale", "is_revoked", "created_at",
	})
	for _, m := range report.Machines {
		lastUsed := ""
		if m.LastUsedAt != nil {
			lastUsed = m.LastUsedAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			strconv.FormatUint(uint64(m.MachineID), 10),
			csvSafe(m.Name),
			csvSafe(m.Description),
			strconv.Itoa(m.CredentialCount),
			lastUsed,
			strconv.FormatBool(m.IsStale),
			strconv.FormatBool(m.IsRevoked),
			m.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
}
