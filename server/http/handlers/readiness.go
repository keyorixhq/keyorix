// readiness.go — ReadinessCheck: a real readiness probe that verifies the server can
// actually serve traffic by pinging its database (core.HealthCheck → SELECT 1). It
// returns 200 when ready and 503 when a dependency is down, so a Kubernetes readiness
// probe stops routing traffic to a replica whose database is unreachable. This is
// distinct from /health (HealthCheck), which is a lightweight liveness signal that must
// NOT depend on the database — a transient DB blip should not restart the pod.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// ReadinessCheck returns a handler for GET /readyz that reports whether the server is
// ready to serve traffic (database reachable). 200 = ready, 503 = not ready. The error
// detail is intentionally generic so internals aren't leaked on an unauthenticated route.
func ReadinessCheck(svc *core.KeyorixCore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		if err := svc.HealthCheck(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "not_ready", "reason": "database unreachable"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	}
}
