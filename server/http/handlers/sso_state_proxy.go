// sso_state_proxy.go — server-side endpoints backing RemoteStorage's
// CreateSSOLoginState/ConsumeSSOLoginState (#521).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// terminates human SSO/SAML login itself (BeginSSO/CompleteSSO,
// BeginSAML/CompleteSAML in internal/core/sso.go) — it just needs somewhere to
// persist the short-lived CSRF-state/nonce row (models.SSOLoginState) it
// issues on redirect and consumes on callback/ACS. Before #521 neither storage
// method had a server route to call at all, so BeginSSO/BeginSAML's very first
// step failed unconditionally under storage.type: remote — SSO login (both
// OIDC and SAML) was 100% broken. These two routes (registered in
// server/http/router.go under /api/v1/system/sso-state, gated on the existing
// system.read/system.write RBAC permissions — the SAME credential a
// RemoteStorage client already needs for every other proxied call) mirror
// setup_tokens_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/sso.go already uses against a local backend — no SSO policy
// decision (state TTL, provider validation, nonce binding) is made here; that
// stays entirely in the calling server's own internal/core.KeyorixCore.
// Crucially, ConsumeSSOLoginStateProxy calls storage.ConsumeSSOLoginState
// directly, so it inherits local_sso.go's atomic read-then-conditional-delete
// verbatim — the single-use-consume guarantee CompleteSSO/CompleteSAML depend
// on survives this HTTP hop unchanged; there is no separate "GET, then DELETE"
// sequence here to reintroduce that TOCTOU race.
//
// Response envelope: like setup_tokens_proxy.go/invitations_proxy.go, these do
// NOT use the package's generic sendSuccess/sendError helpers — they construct
// the exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ssoLoginStateProxyWire mirrors models.SSOLoginState's fields exactly
// (snake_case) — the wire shape internal/storage/store/remote_sso.go's
// ssoLoginStateWire sends/expects. See that type's comment for why every
// field is named explicitly: models.SSOLoginState carries no json tags of its
// own, and this is an internal system-to-system wire format gated on
// system.read/system.write, the same tier that already round-trips full
// user/secret/invitation records.
type ssoLoginStateProxyWire struct {
	ID        uint      `json:"id"`
	State     string    `json:"state"`
	Nonce     string    `json:"nonce"`
	Provider  string    `json:"provider"`
	ReturnTo  string    `json:"return_to"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func newSSOLoginStateProxyWire(s *models.SSOLoginState) ssoLoginStateProxyWire {
	return ssoLoginStateProxyWire{
		ID:        s.ID,
		State:     s.State,
		Nonce:     s.Nonce,
		Provider:  s.Provider,
		ReturnTo:  s.ReturnTo,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
	}
}

func (w ssoLoginStateProxyWire) toModel() *models.SSOLoginState {
	return &models.SSOLoginState{
		ID:        w.ID,
		State:     w.State,
		Nonce:     w.Nonce,
		Provider:  w.Provider,
		ReturnTo:  w.ReturnTo,
		ExpiresAt: w.ExpiresAt,
		CreatedAt: w.CreatedAt,
	}
}

// CreateSSOLoginStateProxy handles POST /api/v1/system/sso-state. The caller
// (the downstream server's own core.KeyorixCore.BeginSSO/BeginSAML) has
// already computed every field — the random state/RelayState token, the nonce
// or AuthnRequest ID, the provider name, the TTL — exactly as it would for
// LocalStorage; this is a raw persist, no policy decision.
func (h *AuthHandler) CreateSSOLoginStateProxy(w http.ResponseWriter, r *http.Request) {
	var body ssoLoginStateProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.State == "" || body.Nonce == "" || body.Provider == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "state, nonce, and provider are required")
		return
	}
	model := body.toModel()
	if err := h.coreService.Storage().CreateSSOLoginState(r.Context(), model); err != nil {
		log.Printf("sso-state proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newSSOLoginStateProxyWire(model))
}

// ssoLoginStateConsumeBody is the wire body for POST
// /api/v1/system/sso-state/consume.
type ssoLoginStateConsumeBody struct {
	State string `json:"state"`
}

// ConsumeSSOLoginStateProxy handles POST /api/v1/system/sso-state/consume. It
// calls storage.ConsumeSSOLoginState directly, so it performs the SAME atomic
// read-then-conditional-delete (`WHERE id = ? AND state = ?`, RowsAffected
// checked) local_sso.go's own ConsumeSSOLoginState does — the single-use-consume
// guarantee CompleteSSO/CompleteSAML depend on: two concurrent callback/ACS
// requests racing on the same state/RelayState must result in exactly one
// success, both locally and now across this HTTP hop. An unknown OR
// already-consumed state cleanly 404s, matching the local backend's identical
// "not found" response for both cases.
func (h *AuthHandler) ConsumeSSOLoginStateProxy(w http.ResponseWriter, r *http.Request) {
	var body ssoLoginStateConsumeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.State == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "state is required")
		return
	}
	st, err := h.coreService.Storage().ConsumeSSOLoginState(r.Context(), body.State)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "SSO login state not found")
			return
		}
		log.Printf("sso-state proxy: consume failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newSSOLoginStateProxyWire(st))
}
