// compliance_controls_csv.go — ExportComplianceControlsCSV: the compliance control
// matrix (each control mapped to ISO 27001 / SOC 2 / NIS2 / DORA / ENS clauses with its
// live pass/gap status) as a CSV attachment for an auditor's spreadsheet. The JSON form is
// GET /compliance/controls; this is the compliance-export-family CSV counterpart, beside
// the audit-log and asset-inventory CSVs.
package handlers

import (
	"encoding/csv"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// ExportComplianceControlsCSV handles GET /api/v1/compliance/controls.csv — the evaluated
// control matrix as a CSV attachment (id, name, area, status, detail, and the framework
// clause refs). Deployment-wide audit.read is enforced by the router (not the
// universal system_viewer baseline — same tier as the JSON endpoint above).
func (h *DashboardHandler) ExportComplianceControlsCSV(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	matrix, err := h.coreService.GetComplianceControls(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to evaluate compliance controls", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="compliance-controls.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"id", "name", "area", "status", "detail", "iso_27001", "soc2", "nis2", "dora", "ens"})
	for _, ctrl := range matrix.Controls {
		_ = cw.Write([]string{
			csvSafe(ctrl.ID),
			csvSafe(ctrl.Name),
			csvSafe(ctrl.Area),
			csvSafe(string(ctrl.Status)),
			csvSafe(ctrl.Detail),
			csvSafe(strings.Join(ctrl.Frameworks.ISO27001, "; ")),
			csvSafe(strings.Join(ctrl.Frameworks.SOC2, "; ")),
			csvSafe(strings.Join(ctrl.Frameworks.NIS2, "; ")),
			csvSafe(strings.Join(ctrl.Frameworks.DORA, "; ")),
			csvSafe(strings.Join(ctrl.Frameworks.ENS, "; ")),
		})
	}
}
