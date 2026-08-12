// webauthn_proxy.go — server-side endpoints backing RemoteStorage's WebAuthn
// storage primitives (ADR-036/ADR-049, finding #517): CreateWebAuthnCredential/
// ListWebAuthnCredentials/GetWebAuthnCredentialByCredID/
// LockWebAuthnCredentialForUpdate/UpdateWebAuthnCredential/
// AdvanceWebAuthnCredentialCounter/DeleteWebAuthnCredential/
// CountWebAuthnCredentials/SetUserWebAuthnEnabled/CreateWebAuthnSession/
// ConsumeWebAuthnSession.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its WebAuthn storage calls to whichever upstream server it's configured
// against, through these routes (registered in server/http/router.go under
// /api/v1/system/webauthn, gated on the existing system.read/system.write RBAC
// permissions — the SAME tier every RemoteStorage credential already needs for
// every other proxied call, so this introduces no new privilege class). Mirrors
// dynamic_secrets_proxy.go/groups_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/webauthn.go already uses against a local backend — NO WebAuthn
// ceremony/ownership/reauth POLICY decision (attestation/assertion verification,
// the re-auth-before-register check, first-enrolment session purge, clone-warning
// handling) is made here; all of that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend.
//
// Unlike MFA's TOTP proxy (remote_mfa.go's IssueMFAChallenge/
// VerifyMFALoginCredentials, a verification proxy — the raw TOTP secret must never
// leave the server that can decrypt it, so the ENTIRE check runs upstream),
// WebAuthn's registered-credential public key and ceremony session state are not
// secret: a spoke server that holds the row can verify an assertion against it
// entirely on its own. So this file is an ordinary CRUD/wire-DTO passthrough,
// matching the Groups/Dynamic-Secrets precedent.
//
// The signature-counter race (#306/#517): AdvanceWebAuthnCredentialCounterProxy is
// the ONE handler here that is not a plain CRUD passthrough. See its doc below and
// storage.Storage's interface doc (internal/core/storage/interface.go) for why the
// counter-advance path needs a single atomic call rather than a
// Lock-then-Update pair — RemoteStorage.WithTransaction is a no-op passthrough
// (internal/storage/store/remote_transaction.go), so this handler performs the
// entire locked compare-and-swap against THIS server's own storage inside one
// request; that is where the real atomicity for a storage.type: remote deployment
// comes from.
//
// Response envelope: like every other proxy in this package, these do NOT use the
// package's generic sendSuccess/sendError helpers — they construct the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// webAuthnCredentialProxyWire mirrors models.WebAuthnCredential's fields exactly
// (snake_case). models.WebAuthnCredential carries no json tags of its own, so
// every field is named explicitly here rather than relying on encoding/json's
// case-insensitive fallback — matching dynamicSecretConfigProxyWire's precedent.
type webAuthnCredentialProxyWire struct {
	ID             uint       `json:"id"`
	UserID         uint       `json:"user_id"`
	CredentialID   []byte     `json:"credential_id"`
	Name           string     `json:"name"`
	CredentialBlob []byte     `json:"credential_blob"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	Disabled       bool       `json:"disabled"`
}

func newWebAuthnCredentialProxyWire(c *models.WebAuthnCredential) webAuthnCredentialProxyWire {
	return webAuthnCredentialProxyWire{
		ID:             c.ID,
		UserID:         c.UserID,
		CredentialID:   c.CredentialID,
		Name:           c.Name,
		CredentialBlob: c.CredentialBlob,
		CreatedAt:      c.CreatedAt,
		LastUsedAt:     c.LastUsedAt,
		Disabled:       c.Disabled,
	}
}

func (w webAuthnCredentialProxyWire) toModel() *models.WebAuthnCredential {
	return &models.WebAuthnCredential{
		ID:             w.ID,
		UserID:         w.UserID,
		CredentialID:   w.CredentialID,
		Name:           w.Name,
		CredentialBlob: w.CredentialBlob,
		CreatedAt:      w.CreatedAt,
		LastUsedAt:     w.LastUsedAt,
		Disabled:       w.Disabled,
	}
}

// webAuthnSessionProxyWire mirrors models.WebAuthnSession's fields exactly.
// TokenHash is tagged `json:"-"` on the model (to keep it out of USER-facing
// responses) — irrelevant here, since this is an internal system-to-system wire
// format gated on system.read/system.write, matching setupTokenProxyWire's
// identical TokenHash precedent.
type webAuthnSessionProxyWire struct {
	ID        uint       `json:"id"`
	UserID    uint       `json:"user_id"`
	TokenHash string     `json:"token_hash"`
	Purpose   string     `json:"purpose"`
	Data      []byte     `json:"data"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func newWebAuthnSessionProxyWire(s *models.WebAuthnSession) webAuthnSessionProxyWire {
	return webAuthnSessionProxyWire{
		ID:        s.ID,
		UserID:    s.UserID,
		TokenHash: s.TokenHash,
		Purpose:   s.Purpose,
		Data:      s.Data,
		ExpiresAt: s.ExpiresAt,
		UsedAt:    s.UsedAt,
		CreatedAt: s.CreatedAt,
	}
}

func (w webAuthnSessionProxyWire) toModel() *models.WebAuthnSession {
	return &models.WebAuthnSession{
		ID:        w.ID,
		UserID:    w.UserID,
		TokenHash: w.TokenHash,
		Purpose:   w.Purpose,
		Data:      w.Data,
		ExpiresAt: w.ExpiresAt,
		UsedAt:    w.UsedAt,
		CreatedAt: w.CreatedAt,
	}
}

// parseWebAuthnUserIDQuery parses the required user_id query parameter shared by
// several of this file's GET handlers.
func parseWebAuthnUserIDQuery(w http.ResponseWriter, r *http.Request) (userID uint, ok bool) {
	v := r.URL.Query().Get("user_id")
	if v == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "user_id query parameter is required")
		return 0, false
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "user_id must be a valid integer")
		return 0, false
	}
	return uint(id), true
}

// CreateWebAuthnCredentialProxy handles POST /api/v1/system/webauthn/credentials.
func (h *AuthHandler) CreateWebAuthnCredentialProxy(w http.ResponseWriter, r *http.Request) {
	var body webAuthnCredentialProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 || len(body.CredentialID) == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and credential_id are required")
		return
	}
	row := body.toModel()
	if err := h.coreService.Storage().CreateWebAuthnCredential(r.Context(), row); err != nil {
		log.Printf("webauthn proxy: create credential failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newWebAuthnCredentialProxyWire(row))
}

// ListWebAuthnCredentialsProxy handles GET
// /api/v1/system/webauthn/credentials?user_id=X.
func (h *AuthHandler) ListWebAuthnCredentialsProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseWebAuthnUserIDQuery(w, r)
	if !ok {
		return
	}
	rows, err := h.coreService.Storage().ListWebAuthnCredentials(r.Context(), userID)
	if err != nil {
		log.Printf("webauthn proxy: list credentials failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]webAuthnCredentialProxyWire, 0, len(rows))
	for _, c := range rows {
		wire = append(wire, newWebAuthnCredentialProxyWire(c))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"credentials": wire})
}

// GetWebAuthnCredentialByCredIDProxy handles GET
// /api/v1/system/webauthn/credentials/lookup?user_id=&credential_id=<base64>.
// Also backs RemoteStorage.LockWebAuthnCredentialForUpdate (see that method's doc,
// internal/storage/store/remote_webauthn.go, for why a standalone HTTP request
// cannot usefully hold a row lock past its own response, and why that is fine: the
// one caller that used to need the lock for correctness now calls
// AdvanceWebAuthnCredentialCounterProxy below instead).
func (h *AuthHandler) GetWebAuthnCredentialByCredIDProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseWebAuthnUserIDQuery(w, r)
	if !ok {
		return
	}
	credIDStr := r.URL.Query().Get("credential_id")
	if credIDStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "credential_id query parameter is required")
		return
	}
	credID, err := base64.StdEncoding.DecodeString(credIDStr)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "credential_id must be valid base64")
		return
	}
	cred, err := h.coreService.Storage().GetWebAuthnCredentialByCredID(r.Context(), credID, userID)
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errWebAuthnCredNotFound)
			return
		}
		log.Printf("webauthn proxy: get credential failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newWebAuthnCredentialProxyWire(cred))
}

// UpdateWebAuthnCredentialProxy handles PUT /api/v1/system/webauthn/credentials/{id}.
// A raw persist (storage.Storage.UpdateWebAuthnCredential is an unconditional
// full-row Save, matching LocalStorage's own semantics exactly) — used by
// rejectIfCloned's best-effort "mark disabled" write. The signature-counter
// advance path does NOT go through this route; see
// AdvanceWebAuthnCredentialCounterProxy below.
func (h *AuthHandler) UpdateWebAuthnCredentialProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid credential id")
		return
	}
	var body webAuthnCredentialProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	// #G79: matches CreateWebAuthnCredentialProxy's validation — this route is
	// an unconditional full-row Save (see the doc above), so a body missing
	// user_id/credential_id would zero those columns on the existing row, not
	// merely leave them unset.
	if body.UserID == 0 || len(body.CredentialID) == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and credential_id are required")
		return
	}
	body.ID = uint(id)
	if err := h.coreService.Storage().UpdateWebAuthnCredential(r.Context(), body.toModel()); err != nil {
		log.Printf("webauthn proxy: update credential failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}

// advanceWebAuthnCounterProxyBody is the wire body for
// AdvanceWebAuthnCredentialCounterProxy.
type advanceWebAuthnCounterProxyBody struct {
	CredentialID []byte    `json:"credential_id"`
	UserID       uint      `json:"user_id"`
	NewBlob      []byte    `json:"new_blob"`
	NewSignCount uint32    `json:"new_sign_count"`
	LastUsedAt   time.Time `json:"last_used_at"`
}

// AdvanceWebAuthnCredentialCounterProxy handles PATCH
// /api/v1/system/webauthn/credentials/advance-counter — the ONE handler in this
// file that is not a plain CRUD passthrough.
//
// It calls storage.Storage.AdvanceWebAuthnCredentialCounter directly
// (h.coreService.Storage() reaches the identical primitive this server's own
// local /auth/webauthn login path uses via persistUpdatedCredential), which
// performs the ENTIRE locked compare-and-swap — re-reading the row's CURRENT
// persisted counter under a row lock (Postgres: SELECT ... FOR UPDATE) and only
// conditionally overwriting it — inside this single request, against THIS
// server's own storage. That is the critical property a downstream (spoke) server
// depends on for security under storage.type: remote: two concurrent logins racing
// the same credential (e.g. a cloned authenticator authenticating alongside the
// legitimate device) must never let the loser's stale, lower counter clobber the
// winner's already-persisted higher one, even when each login is itself proxied
// from a DIFFERENT spoke process — closing exactly the race a naive
// Lock-then-Update pair over two separate HTTP calls would reopen (see this
// file's package doc, and storage.Storage's interface doc, for the full
// reasoning).
func (h *AuthHandler) AdvanceWebAuthnCredentialCounterProxy(w http.ResponseWriter, r *http.Request) {
	var body advanceWebAuthnCounterProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if len(body.CredentialID) == 0 || body.UserID == 0 || len(body.NewBlob) == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "credential_id, user_id, and new_blob are required")
		return
	}
	advanced, err := h.coreService.Storage().AdvanceWebAuthnCredentialCounter(
		r.Context(), body.CredentialID, body.UserID, body.NewBlob, body.NewSignCount, body.LastUsedAt)
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errWebAuthnCredNotFound)
			return
		}
		log.Printf("webauthn proxy: advance counter failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"advanced": advanced})
}

// DeleteWebAuthnCredentialProxy handles DELETE
// /api/v1/system/webauthn/users/{userId}/credentials/{id} — scoped by user (in
// the path, not just a query parameter) so a caller can't delete another user's
// passkey by id, mirroring the local implementation's own ownership check.
func (h *AuthHandler) DeleteWebAuthnCredentialProxy(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid credential id")
		return
	}
	if err := h.coreService.Storage().DeleteWebAuthnCredential(r.Context(), uint(userID), uint(id)); err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errWebAuthnCredNotFound)
			return
		}
		log.Printf("webauthn proxy: delete credential failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}

// CountWebAuthnCredentialsProxy handles GET
// /api/v1/system/webauthn/credentials/count?user_id=X.
func (h *AuthHandler) CountWebAuthnCredentialsProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseWebAuthnUserIDQuery(w, r)
	if !ok {
		return
	}
	n, err := h.coreService.Storage().CountWebAuthnCredentials(r.Context(), userID)
	if err != nil {
		log.Printf("webauthn proxy: count credentials failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"count": n})
}

// setUserWebAuthnEnabledProxyBody is the wire body for SetUserWebAuthnEnabledProxy.
type setUserWebAuthnEnabledProxyBody struct {
	Enabled bool `json:"enabled"`
}

// SetUserWebAuthnEnabledProxy handles PUT
// /api/v1/system/webauthn/users/{userId}/webauthn-enabled.
func (h *AuthHandler) SetUserWebAuthnEnabledProxy(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
		return
	}
	var body setUserWebAuthnEnabledProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if err := h.coreService.Storage().SetUserWebAuthnEnabled(r.Context(), uint(userID), body.Enabled); err != nil {
		log.Printf("webauthn proxy: set webauthn enabled failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}

// CreateWebAuthnSessionProxy handles POST /api/v1/system/webauthn/sessions.
func (h *AuthHandler) CreateWebAuthnSessionProxy(w http.ResponseWriter, r *http.Request) {
	var body webAuthnSessionProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 || body.TokenHash == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and token_hash are required")
		return
	}
	row := body.toModel()
	if err := h.coreService.Storage().CreateWebAuthnSession(r.Context(), row); err != nil {
		log.Printf("webauthn proxy: create session failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newWebAuthnSessionProxyWire(row))
}

// webAuthnSessionConsumeProxyBody is the wire body for
// ConsumeWebAuthnSessionProxy.
type webAuthnSessionConsumeProxyBody struct {
	TokenHash string    `json:"token_hash"`
	Now       time.Time `json:"now"`
}

// ConsumeWebAuthnSessionProxy handles POST
// /api/v1/system/webauthn/sessions/consume. Calls
// storage.Storage.ConsumeWebAuthnSession directly, so this inherits
// local_webauthn.go's own atomic "UPDATE ... WHERE used_at IS NULL AND
// expires_at > ?" single-use guarantee unchanged — the single round trip a
// concurrent-consume race resolves in, mirroring ConsumeSetupTokenProxy's #510
// precedent. Every failure (no matching row, already used, expired, or a genuine
// storage error) collapses to the same 404 — LocalStorage's own
// ConsumeWebAuthnSession already returns one generic "invalid or expired webauthn
// session" error for all of those cases, so this loses no information the local
// path ever exposed.
func (h *AuthHandler) ConsumeWebAuthnSessionProxy(w http.ResponseWriter, r *http.Request) {
	var body webAuthnSessionConsumeProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.TokenHash == "" || body.Now.IsZero() {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "token_hash and now are required")
		return
	}
	sess, err := h.coreService.Storage().ConsumeWebAuthnSession(r.Context(), body.TokenHash, body.Now)
	if err != nil {
		writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "invalid or expired webauthn session")
		return
	}
	writeRemoteAPISuccess(w, newWebAuthnSessionProxyWire(sess))
}
