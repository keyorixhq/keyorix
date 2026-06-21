// admin_jobs.go — on-demand triggers for the notification/alert jobs that
// otherwise only run on their background schedulers (anomaly alerting, rotation and
// expiry reminders, the compliance digest). After an incident or a config change an
// operator often needs to dispatch these immediately rather than wait for the next
// tick. All are deployment-wide admin actions, gated by system.write in the router.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// AdminJobsHandler exposes the scheduled jobs as manual triggers.
type AdminJobsHandler struct {
	coreService *core.KeyorixCore
}

// NewAdminJobsHandler creates a new AdminJobsHandler.
func NewAdminJobsHandler(coreService *core.KeyorixCore) *AdminJobsHandler {
	return &AdminJobsHandler{coreService: coreService}
}

// RunAnomalyAlerts handles POST /api/v1/admin/jobs/anomaly-alerts — broadcast alerts
// for any new (unalerted) anomaly findings now. Returns {alerted}.
func (h *AdminJobsHandler) RunAnomalyAlerts(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	n, err := h.coreService.AlertNewAnomalies(r.Context())
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"alerted": n}, "")
}

// RunRotationReminders handles POST /api/v1/admin/jobs/rotation-reminders — send
// rotation-due reminders now. Returns {sent}.
func (h *AdminJobsHandler) RunRotationReminders(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	n, err := h.coreService.SendRotationReminders(r.Context())
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"sent": n}, "")
}

// RunExpiryReminders handles POST /api/v1/admin/jobs/expiry-reminders?lead_days=N —
// send expiry reminders for secrets expiring within the lead window (default 14 when
// lead_days is omitted or non-positive). Returns {sent}.
func (h *AdminJobsHandler) RunExpiryReminders(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	leadDays := 0 // core applies the default when <= 0
	if v := r.URL.Query().Get("lead_days"); v != "" {
		if d, perr := strconv.Atoi(v); perr == nil {
			leadDays = d
		}
	}
	n, err := h.coreService.SendExpiryReminders(r.Context(), leadDays)
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"sent": n}, "")
}

// RunComplianceDigest handles POST /api/v1/admin/jobs/compliance-digest — broadcast the
// compliance digest now. Returns {sent} (false when there were no recipients/changes).
func (h *AdminJobsHandler) RunComplianceDigest(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	sent, err := h.coreService.SendComplianceDigest(r.Context())
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"sent": sent}, "")
}
