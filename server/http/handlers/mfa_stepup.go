// mfa_stepup.go — HTTP handler for explicit MFA step-up re-verification.
// POST /api/v1/auth/mfa/stepup lets an already-authenticated user re-verify
// their TOTP code (or a recovery code) to open a 15-minute window for reading
// "restricted" classified secrets without going through a full re-login.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// MFAStepUp handles POST /api/v1/auth/mfa/stepup. The caller must be
// authenticated (session or PAT). On success, a short-lived MFAStepupToken is
// recorded server-side, enabling the classification gate to permit reads of
// "restricted" secrets for the configured window (default 15 minutes).
func (h *AuthHandler) MFAStepUp(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	if strings.TrimSpace(body.Code) == "" {
		sendError(w, "BadRequest", "code is required", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.VerifyMFAStepUp(r.Context(), userCtx.UserID, body.Code); err != nil {
		sendError(w, "Unauthorized", err.Error(), http.StatusUnauthorized, nil)
		return
	}
	sendSuccess(w, nil, "MFA step-up verified. Restricted secrets are accessible for 15 minutes.")
}
