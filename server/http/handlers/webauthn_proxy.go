// webauthn_proxy.go — server-side endpoints backing RemoteStorage's WebAuthn
// storage primitives (ADR-036/ADR-049, finding #517):
// ListWebAuthnCredentials/GetWebAuthnCredentialByCredID/
// LockWebAuthnCredentialForUpdate/UpdateWebAuthnCredential/
// AdvanceWebAuthnCredentialCounter/CountWebAuthnCredentials/
// CreateWebAuthnSession/ConsumeWebAuthnSession. (CreateWebAuthnCredentialProxy/
// DeleteWebAuthnCredentialProxy/SetUserWebAuthnEnabledProxy were deleted --
// G80 liveness sweep found no live caller for any of them; see
// docs/g80-remediation-notes.md.)
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
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
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
//
// #1714: this used to be a raw, unconditional full-row Save trusting the
// entire caller-supplied body -- an authz-ceiling bypass, not merely an audit
// gap (reclassified from the original "audit-completeness" framing). Two
// distinct things a system.write holder could do with the old code, neither
// requiring any WebAuthn ceremony at all:
//   - Reassign a credential's ownership: the handler applied body.UserID to
//     the row unconditionally, with no check that it matched the row the URL
//     {id} actually names.
//   - Silently re-enable a clone-disabled credential (disabled: false),
//     directly contradicting models.WebAuthnCredential's own documented
//     invariant ("Never auto-re-enabled").
//
// The route's ONLY legitimate purpose, repo-wide, is rejectIfCloned's
// disable-on-clone write (internal/core/webauthn.go is the sole internal/core
// caller of storage.Storage.UpdateWebAuthnCredential). This handler is now
// narrowed to exactly that: identify the row by (credential_id, user_id) --
// which scopes ownership by construction, the same reasoning
// rejectIfCloned's own lookup already relies on (#307) -- reject outright if
// that pair doesn't resolve to the URL's {id}, and reject outright unless
// disabled is exactly true. Routes through
// KeyorixCore.MarkWebAuthnCredentialClonedByLookup, which performs the
// mutation and the EventWebAuthnCloneDetected audit write as one unit; see
// that function's doc. The signature-counter advance path does NOT go
// through this route; see AdvanceWebAuthnCredentialCounterProxy below.
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
	if body.UserID == 0 || len(body.CredentialID) == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and credential_id are required")
		return
	}
	// The only transition this route ever legitimately performs is
	// disable-on-clone (false -> true). Anything else -- re-enabling, or a
	// body that omits disabled entirely (Go's zero value is false) -- is
	// rejected outright, not silently ignored: the model's own invariant is
	// "never auto-re-enabled," so there is no reachable legitimate use of
	// disabled: false via this route, ever.
	if !body.Disabled {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY",
			"this route only disables a credential on a clone-detection signal; disabled must be true")
		return
	}
	_, err = h.coreService.MarkWebAuthnCredentialClonedByLookup(r.Context(), body.CredentialID, body.UserID, uint(id), clientIP(r))
	if err != nil {
		if errors.Is(err, core.ErrWebAuthnCredentialIDMismatch) {
			// (credential_id, user_id) resolved to a REAL, owned row, but not the
			// one the URL named -- the caller is targeting one credential's ID
			// while authenticating the request against a different one's
			// identity. Rejected BEFORE any mutation (see the domain function's
			// own doc) -- log it, since this is either a caller bug or an
			// attempt to probe/confuse the id<->identity binding.
			log.Printf("webauthn proxy: update credential: URL id %d does not match the credential named by "+
				"the body's (user_id=%d, credential_id); rejecting, nothing changed", id, body.UserID)
			writeRemoteAPIError(w, http.StatusConflict, "ID_MISMATCH",
				"the credential identified by user_id and credential_id does not match the id in the URL")
			return
		}
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errWebAuthnCredNotFound)
			return
		}
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
// ConsumeWebAuthnSessionProxy. It used to also carry a caller-supplied `now`
// forwarded straight into the expiry comparison — removed (G-wave6, same
// class as users_crud.go's mfaChallengeLookupBody): a remote caller could
// manipulate the effective "current time" used to decide whether a WebAuthn
// ceremony session is still valid. This server now always uses its own
// clock for that comparison.
type webAuthnSessionConsumeProxyBody struct {
	TokenHash string `json:"token_hash"`
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
	if body.TokenHash == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "token_hash is required")
		return
	}
	// This server's own clock, never a caller-supplied value — see
	// webAuthnSessionConsumeProxyBody's doc comment. Passed as this
	// process's local time, not pre-converted to UTC here: G80 final
	// documented-exception sweep (2026-08-26) found this comment previously
	// claimed "no BeforeSave hook normalizes models.WebAuthnSession.ExpiresAt,
	// so writes and reads must share the same (local) Location convention" —
	// that was stale even at the time it was written. models.WebAuthnSession
	// DOES have a BeforeSave hook (models.go:603) that normalizes ExpiresAt
	// to UTC on every write. The comparison is safe for a different reason
	// than the old text claimed: ConsumeWebAuthnSession itself independently
	// calls `now.UTC()` before comparing (local_webauthn.go:163), so this
	// handler's local `time.Now()` is normalized at the storage layer
	// regardless of what Location it carries when it arrives here.
	sess, err := h.coreService.Storage().ConsumeWebAuthnSession(r.Context(), body.TokenHash, time.Now())
	if err != nil {
		writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "invalid or expired webauthn session")
		return
	}
	writeRemoteAPISuccess(w, newWebAuthnSessionProxyWire(sess))
}
