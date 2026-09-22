// secrets_status_proxy.go — server-side endpoint backing RemoteStorage's
// TransitionSecretStatus storage primitive (StateTransitionMissingCAS: the
// suspend/resume TOCTOU class, mirroring #388's machine-identity fix and
// #412's project-invitation fix for the same recurring bug shape).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// proxies its secret status-transition storage calls to whichever upstream
// server it's configured against, through this route (registered in
// server/http/router.go under /api/v1/system/secrets/{id}/transition-status,
// gated on the existing system.write RBAC permission — the SAME credential a
// RemoteStorage client already needs for every other proxied call in this
// group, so this introduces no new privilege class).
//
// This is a thin passthrough onto storage.Storage.TransitionSecretStatus, the
// SAME primitive internal/core/secret_suspend.go's SuspendSecret/ResumeSecret
// use against a local backend — NO suspend/resume POLICY decision (who may
// suspend, the idempotent already-suspended/already-active no-op, audit
// logging) is made here; all of that stays entirely in the CALLING server's
// own internal/core.KeyorixCore, exactly as it does against a local backend.
// This route DOES apply the conditional "WHERE id = ? AND status = ?" write
// itself — not because that's this server's OWN policy decision, but because
// no real transaction can span the HTTP hop back to the calling server
// (RemoteStorage.WithTransaction is a no-op passthrough), so whichever server
// ultimately owns the row is the only one that CAN enforce the atomicity
// SuspendSecret/ResumeSecret rely on. See the storage.Storage interface doc
// (internal/core/storage/interface.go) for the full reasoning.
//
// Response envelope: like the other proxies, this does NOT use the package's
// generic sendSuccess/sendError helpers — it constructs the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// transitionSecretStatusProxyBody is the request body
// TransitionSecretStatusProxy expects: the full secret row the caller already
// mutated in memory (secret.Status/UpdatedAt already set to the target
// values), plus the fromStatus the caller observed via GetSecret immediately
// before mutating it — mirroring transitionMachineIdentityStateBody's shape
// exactly. Secret decodes into *models.SecretNode directly (it carries no
// json tags of its own beyond ValueStored's `json:"-"`, so a Go-to-Go round
// trip between the handler and RemoteStorage's identical type preserves every
// field exactly, the same choice GetSecretIncludingDeletedProxy already makes
// for the identical type).
type transitionSecretStatusProxyBody struct {
	Secret     *models.SecretNode `json:"secret"`
	FromStatus string             `json:"from_status"`
}

// TransitionSecretStatusProxy handles PUT
// /api/v1/system/secrets/{id}/transition-status. Runs the SAME conditional
// "WHERE id = ? AND status = ?" write core.KeyorixCore.SuspendSecret/
// ResumeSecret already rely on against a local backend — see the package
// doc's reasoning for why this is a dedicated route rather than a generic
// UpdateSecret proxy call.
//
// #G79: the underlying storage.TransitionSecretStatus call is a
// `Select("*")` full-row update (see local_secrets.go), and every legitimate
// caller (SuspendSecret/ResumeSecret) only ever mutates Status and UpdatedAt
// on the row it just fetched — never OwnerID/ParentID/Classification/
// ExpiresAt/read-quota counters/anything else. Without that constraint
// enforced here, a client-supplied wire body could rewrite any of those
// under cover of a status transition. Re-fetch the authoritative row and
// apply only Status/UpdatedAt from the wire onto it.
func (h *SecretHandler) TransitionSecretStatusProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid secret id")
		return
	}
	var body transitionSecretStatusProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Secret == nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "secret is required")
		return
	}
	if body.FromStatus == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "from_status is required")
		return
	}
	existing, err := h.coreService.Storage().GetSecret(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "secret not found")
			return
		}
		log.Printf("secrets proxy: transition status lookup failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	// #TransitionSecretStatus (system-proxy-target-authority audit): the
	// package doc's "no suspend/resume POLICY decision is made here" framing
	// was correct about WHO decides, but the human-facing SuspendSecret/
	// ResumeSecret routes enforce that decision via
	// RequireScopedSecretPermission(permSecretsWrite, "id") at the HTTP
	// TRANSPORT layer -- core.SuspendSecret/ResumeSecret themselves apply no
	// check (by design, same "transport enforces, core doesn't" pattern as
	// core.UpdateUser). This route's only transport is the /system group's
	// blanket system.write, so it never got the transport-layer check at all
	// -- a system.write-only caller could suspend (deny read access to) OR,
	// worse, silently RESUME a secret an admin had deliberately suspended as
	// an incident-response containment action, undoing that decision with no
	// real-time signal. Re-derive the same scoped secrets.write check both
	// directions need, identically -- the human-facing route requires it for
	// both /suspend and /resume.
	actorType, actorID := requestActorKindAndID(r)
	if allowed, aerr := h.coreService.AuthorizeSecretPrincipal(r.Context(), actorType, actorID, uint(id), "secrets.write"); aerr != nil {
		log.Printf("secrets proxy: transition status authorize failed: %v", aerr)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(aerr))
		return
	} else if !allowed {
		writeRemoteAPIError(w, http.StatusForbidden, "PERMISSION_DENIED", "not authorized on this secret")
		return
	}
	existing.Status = body.Secret.Status
	existing.UpdatedAt = body.Secret.UpdatedAt
	matched, err := h.coreService.Storage().TransitionSecretStatus(r.Context(), existing, body.FromStatus)
	if err != nil {
		log.Printf("secrets proxy: transition status failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": matched})
}
