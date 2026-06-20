// secrets_name_conformance_deployment.go — DeploymentSecretNameConformance handler: the
// org-wide naming-policy conformance report (every project's live secrets whose names
// violate the current naming policy). Deployment-wide system.read is enforced by the
// router. Parallels the per-project SecretNameConformance handler.
package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// DeploymentSecretNameConformance handles GET /api/v1/secrets/name-conformance — every
// live secret across all projects whose name violates the current naming policy, each
// tagged with its project. Returns an empty (policy_enabled false) report when no naming
// policy is configured.
func (h *SecretHandler) DeploymentSecretNameConformance(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	report, err := h.coreService.DeploymentSecretNameConformance(r.Context())
	if err != nil {
		h.sendError(w, "InternalError", "Failed to evaluate naming-policy conformance", http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, report, "")
}
