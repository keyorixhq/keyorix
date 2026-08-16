// secret_version_diff.go — GET /api/v1/secrets/{id}/versions/{from}/diff/{to}
//
// Returns a metadata diff between two versions of a secret. Values (encrypted
// ciphertext) are never compared — only classification, expiry, read count, and
// the current ACL snapshot.
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// DiffSecretVersions handles GET /api/v1/secrets/{id}/versions/{from}/diff/{to}.
// It gates on secrets.read (enforced by the route middleware) and returns the
// metadata diff between the two named version numbers.
func (h *SecretHandler) DiffSecretVersions(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	fromStr := chi.URLParam(r, "from")
	from, err := strconv.Atoi(fromStr)
	if err != nil || from <= 0 {
		h.sendError(w, "InvalidParameter", "from version must be a positive integer", http.StatusBadRequest, nil)
		return
	}

	toStr := chi.URLParam(r, "to")
	to, err := strconv.Atoi(toStr)
	if err != nil || to <= 0 {
		h.sendError(w, "InvalidParameter", "to version must be a positive integer", http.StatusBadRequest, nil)
		return
	}

	diff, err := h.coreService.DiffSecretVersions(r.Context(), uint(id), from, to)
	if err != nil {
		log.Printf("DiffSecretVersions error: %v", err)
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found") || strings.Contains(msg, "version") && strings.Contains(msg, "not found"):
			h.sendError(w, "NotFound", msg, http.StatusNotFound, nil)
		case strings.Contains(msg, "validation") || strings.Contains(msg, "must differ") || strings.Contains(msg, "must be positive"):
			h.sendError(w, "ValidationError", msg, http.StatusBadRequest, nil)
		default:
			h.sendError(w, "InternalError", "Failed to diff secret versions", http.StatusInternalServerError, nil)
		}
		return
	}

	// The route is gated on secrets.read (see router.go), but the dedicated ACL
	// endpoint (GET /{id}/acl) is intentionally gated tighter, on secrets.manage
	// — ACL membership (who has explicit access to this secret) is more
	// sensitive than the version-metadata diff itself. core.DiffSecretVersions
	// includes ACLUserIDs as a convenience snapshot for callers who already hold
	// manage rights (e.g. the embedded-mode CLI), so strip it here — matching
	// the same in-handler tiered-visibility pattern ListSecrets uses — for any
	// caller who only cleared the read-level route gate. Degraded exists solely
	// to qualify ACLUserIDs' trustworthiness, so it is meaningless (and
	// potentially confusing) once ACLUserIDs itself is hidden.
	if allowed, aerr := h.coreService.AuthorizeSecretPrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), uint(id), permSecretsManage); aerr != nil || !allowed {
		diff.ACLUserIDs = nil
		diff.Degraded = false
	}

	h.sendSuccess(w, diff, "")
}
