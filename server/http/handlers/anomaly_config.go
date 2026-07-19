// anomaly_config.go — GET/PUT /api/v1/admin/anomaly-config
//
// Allows operators to read and update the runtime anomaly detection
// configuration (lookback window, quarantine, off-hours, ML parameters)
// without restarting the server.  Changes are persisted to the DB and picked
// up by the anomaly detection scheduler on its next pass.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetAnomalyConfig handles GET /api/v1/admin/anomaly-config.
// Returns the current persisted anomaly detection configuration (or defaults).
func GetAnomalyConfig(w http.ResponseWriter, r *http.Request) {
	coreService := middleware.GetCoreServiceFromContext(r.Context())
	if coreService == nil {
		sendError(w, "InternalError", "Core service not available", http.StatusInternalServerError, nil)
		return
	}
	cfg, err := coreService.GetAnomalyConfig(r.Context())
	if err != nil {
		sendError(w, "InternalError", "Failed to retrieve anomaly config", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"config": cfg}, "")
}

// UpdateAnomalyConfig handles PUT /api/v1/admin/anomaly-config.
// Replaces the current anomaly detection configuration; the detection scheduler
// will pick up the change on its next pass without a restart.
func UpdateAnomalyConfig(w http.ResponseWriter, r *http.Request) {
	coreService := middleware.GetCoreServiceFromContext(r.Context())
	if coreService == nil {
		sendError(w, "InternalError", "Core service not available", http.StatusInternalServerError, nil)
		return
	}

	var cfg models.AnomalyConfigRecord
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	var updatedBy string
	if u := middleware.GetUserFromContext(r.Context()); u != nil {
		updatedBy = u.Username
	}

	if err := coreService.UpdateAnomalyConfig(r.Context(), &cfg, updatedBy); err != nil {
		sendError(w, "InternalError", "Failed to save anomaly config", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"config": cfg}, "")
}
