package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/version"
)

// processStart is captured when the package loads (≈ server start) so /health can report
// a real uptime.
var processStart = time.Now()

// HealthCheck handles GET /health — a lightweight liveness signal: it reports that the
// process is up and responsive. It deliberately does NOT check the database or other
// dependencies (that is /readyz's job) — a transient dependency outage should not cause
// the liveness probe to fail and restart the pod.
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"uptime":    time.Since(processStart).String(),
		"version":   version.Version,
		"commit":    version.Commit,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	if err := json.NewEncoder(w).Encode(health); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
