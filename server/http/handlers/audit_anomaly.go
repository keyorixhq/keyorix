// audit_anomaly.go — ListAnomalyAlerts and AcknowledgeAnomalyAlert handlers.
//
// For audit log handlers see audit.go.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListAnomalyAlerts handles GET /api/v1/anomalies
func ListAnomalyAlerts(w http.ResponseWriter, r *http.Request) {
	coreService := middleware.GetCoreServiceFromContext(r.Context())
	if coreService == nil {
		sendError(w, "InternalError", "Core service not available", http.StatusInternalServerError, nil)
		return
	}
	// ?acknowledged=true|false filters server-side; nil (param absent) returns
	// all. ?unacknowledged=true is the legacy alias (still used by the CLI).
	var acknowledged *bool
	if v := r.URL.Query().Get("acknowledged"); v != "" {
		b := v == "true" || v == "1"
		acknowledged = &b
	} else if r.URL.Query().Get("unacknowledged") == "true" {
		b := false
		acknowledged = &b
	}
	detector := core.NewAnomalyDetector(coreService.Storage())
	alerts, err := detector.ListAlerts(r.Context(), acknowledged)
	if err != nil {
		sendError(w, "InternalError", "Failed to list anomaly alerts", http.StatusInternalServerError, nil)
		return
	}
	// Optional ?severity=low|medium|high and ?alertType=off_hours|new_ip|new_user|
	// frequency_spike narrow the list server-side (an empty value is no constraint).
	alerts = core.FilterAlerts(alerts, r.URL.Query().Get("severity"), r.URL.Query().Get("alertType"))
	sendSuccess(w, map[string]interface{}{"alerts": alerts, "total": len(alerts)}, "")
}

// AcknowledgeAnomalyAlert handles POST /api/v1/anomalies/{id}/acknowledge
func AcknowledgeAnomalyAlert(w http.ResponseWriter, r *http.Request) {
	coreService := middleware.GetCoreServiceFromContext(r.Context())
	if coreService == nil {
		sendError(w, "InternalError", "Core service not available", http.StatusInternalServerError, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		sendError(w, "BadRequest", "Invalid alert ID", http.StatusBadRequest, nil)
		return
	}
	detector := core.NewAnomalyDetector(coreService.Storage())
	if err := detector.AcknowledgeAlert(r.Context(), uint(id)); err != nil {
		sendError(w, "InternalError", "Failed to acknowledge alert", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"acknowledged": true}, "")
}
