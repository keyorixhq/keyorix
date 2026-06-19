// secrets_policy.go — SecretPolicy handler: the active create-time secret policies.
package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// SecretPolicy handles GET /api/v1/secrets/policy — the active secret-name and
// secret-value policies (rule flags only, no denylist values), so a client can show
// the conventions and pre-validate. Authenticated; no special permission (these are
// the rules every creator is held to, not sensitive data).
func (h *SecretHandler) SecretPolicy(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	h.sendSuccess(w, h.coreService.SecretPolicies(), "")
}
