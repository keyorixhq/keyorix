// setup_tokens_proxy.go — server-side endpoints backing RemoteStorage's
// CreateSetupToken/GetSetupTokenByHash/SupersedeActiveSetupTokens/
// MarkSetupTokenConsumed/MarkSetupTokenExpired/CountSetupTokensSince (#510).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its setup-token storage calls to whichever upstream server it's configured
// against, through these six routes (registered in server/http/router.go under
// /api/v1/system/setup-tokens, gated on the existing system.read/system.write RBAC
// permissions — the SAME credential a RemoteStorage client already needs for every
// other proxied call, e.g. full user CRUD and the #507 invitations proxy, so this
// introduces no new privilege class). This mirrors invitations_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/setup_token.go and setup_consume.go already use against a local
// backend — no setup-token POLICY decision (purpose validation, TTL computation,
// which transitions are legal) is made here; that stays entirely in the CALLING
// server's own internal/core.KeyorixCore. Crucially, ConsumeSetupTokenProxy calls
// storage.MarkSetupTokenConsumed directly, so it inherits local_auth.go's
// conditional `WHERE id = ? AND state = 'active'` write verbatim — the
// single-use-consume race guarantee consumeInspectedToken (setup_token.go) depends
// on survives this HTTP hop unchanged; there is no separate "check active, then
// write" sequence here to reintroduce that TOCTOU.
//
// Response envelope: like invitations_proxy.go/login_attempts_proxy.go, these do
// NOT use the package's generic sendSuccess/sendError helpers — they construct the
// exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)


// setupTokenProxyWire mirrors models.SetupToken's fields exactly (snake_case) — the
// wire shape internal/storage/store/remote_auth.go's setupTokenWire sends/expects.
// See that type's comment for why every field is named explicitly rather than
// relying on encoding/json's case-insensitive fallback (models.SetupToken carries
// no json tags of its own besides TokenHash's `json:"-"`, which exists to keep the
// hash out of USER-facing responses — irrelevant here, since this is an internal
// system-to-system wire format gated on system.read/system.write).
type setupTokenProxyWire struct {
	ID            uint       `json:"id"`
	TokenHash     string     `json:"token_hash"`
	Purpose       string     `json:"purpose"`
	SubjectUserID *uint      `json:"subject_user_id"`
	SubjectEmail  string     `json:"subject_email"`
	InvitationID  *uint      `json:"invitation_id"`
	State         string     `json:"state"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CreatedBy     uint       `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	ConsumedAt    *time.Time `json:"consumed_at"`
}

func newSetupTokenProxyWire(t *models.SetupToken) setupTokenProxyWire {
	return setupTokenProxyWire{
		ID:            t.ID,
		TokenHash:     t.TokenHash,
		Purpose:       t.Purpose,
		SubjectUserID: t.SubjectUserID,
		SubjectEmail:  t.SubjectEmail,
		InvitationID:  t.InvitationID,
		State:         t.State,
		ExpiresAt:     t.ExpiresAt,
		CreatedBy:     t.CreatedBy,
		CreatedAt:     t.CreatedAt,
		ConsumedAt:    t.ConsumedAt,
	}
}

func (w setupTokenProxyWire) toModel() *models.SetupToken {
	return &models.SetupToken{
		ID:            w.ID,
		TokenHash:     w.TokenHash,
		Purpose:       w.Purpose,
		SubjectUserID: w.SubjectUserID,
		SubjectEmail:  w.SubjectEmail,
		InvitationID:  w.InvitationID,
		State:         w.State,
		ExpiresAt:     w.ExpiresAt,
		CreatedBy:     w.CreatedBy,
		CreatedAt:     w.CreatedAt,
		ConsumedAt:    w.ConsumedAt,
	}
}

// CreateSetupTokenProxy handles POST /api/v1/system/setup-tokens. The caller (the
// downstream server's own core.KeyorixCore.IssueSetupToken) has already computed
// every field — the hash, purpose, TTL, subject — exactly as it would for
// LocalStorage; this is a raw persist, no policy decision.
func (h *AuthHandler) CreateSetupTokenProxy(w http.ResponseWriter, r *http.Request) {
	var body setupTokenProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.TokenHash == "" || body.Purpose == "" || body.SubjectEmail == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "token_hash, purpose, and subject_email are required")
		return
	}
	created, err := h.coreService.Storage().CreateSetupToken(r.Context(), body.toModel())
	if err != nil {
		log.Printf("setup-tokens proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newSetupTokenProxyWire(created))
}

// GetSetupTokenByHashProxy handles GET /api/v1/system/setup-tokens/by-hash/{hash} —
// the consumption lookup, keyed on the SHA-256 hex digest, never the raw plaintext
// token.
func (h *AuthHandler) GetSetupTokenByHashProxy(w http.ResponseWriter, r *http.Request) {
	hash := chi.URLParam(r, "hash")
	if hash == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "hash is required")
		return
	}
	tok, err := h.coreService.Storage().GetSetupTokenByHash(r.Context(), hash)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "setup token not found")
			return
		}
		log.Printf("setup-tokens proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newSetupTokenProxyWire(tok))
}

// setupTokenSupersedeBody is the wire body for POST
// /api/v1/system/setup-tokens/supersede.
type setupTokenSupersedeBody struct {
	Purpose      string `json:"purpose"`
	SubjectEmail string `json:"subject_email"`
}

// SupersedeSetupTokensProxy handles POST /api/v1/system/setup-tokens/supersede. It
// performs the SAME `WHERE purpose = ? AND subject_email = ? AND state = 'active'`
// bulk UPDATE local_auth.go's own SupersedeActiveSetupTokens does — a reissue kills
// every prior active link for the same (purpose, email) atomically.
func (h *AuthHandler) SupersedeSetupTokensProxy(w http.ResponseWriter, r *http.Request) {
	var body setupTokenSupersedeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.Purpose == "" || body.SubjectEmail == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "purpose and subject_email are required")
		return
	}
	if err := h.coreService.Storage().SupersedeActiveSetupTokens(r.Context(), body.Purpose, body.SubjectEmail); err != nil {
		log.Printf("setup-tokens proxy: supersede failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"superseded": true})
}

// setupTokenConsumeBody is the wire body for POST
// /api/v1/system/setup-tokens/{id}/consume.
type setupTokenConsumeBody struct {
	ConsumedAt time.Time `json:"consumed_at"`
}

// ConsumeSetupTokenProxy handles POST /api/v1/system/setup-tokens/{id}/consume. It
// performs the SAME conditional `WHERE id = ? AND state = 'active'` write
// LocalStorage's own MarkSetupTokenConsumed does (h.coreService.Storage() reaches
// the identical storage.Storage primitive this server's local /auth/setup/consume
// path uses), returning whether it actually matched a still-active row — the single
// round trip a concurrent-consume race resolves in. This is the single-use-consume
// guarantee: two concurrent consume requests racing on the same token must result
// in exactly one success, both locally and now across this HTTP hop.
func (h *AuthHandler) ConsumeSetupTokenProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid setup token ID")
		return
	}
	var body setupTokenConsumeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.ConsumedAt.IsZero() {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "consumed_at is required")
		return
	}
	consumed, err := h.coreService.Storage().MarkSetupTokenConsumed(r.Context(), uint(id), body.ConsumedAt)
	if err != nil {
		log.Printf("setup-tokens proxy: consume failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"consumed": consumed})
}

// ExpireSetupTokenProxy handles POST /api/v1/system/setup-tokens/{id}/expire (lazy
// expiry on read, mirroring local_auth.go's MarkSetupTokenExpired).
func (h *AuthHandler) ExpireSetupTokenProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid setup token ID")
		return
	}
	if err := h.coreService.Storage().MarkSetupTokenExpired(r.Context(), uint(id)); err != nil {
		log.Printf("setup-tokens proxy: expire failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"expired": true})
}

// CountSetupTokensSinceProxy handles GET
// /api/v1/system/setup-tokens/count?purpose=X&subject_email=Y&since=RFC3339,
// backing resend throttling and the daily cap.
func (h *AuthHandler) CountSetupTokensSinceProxy(w http.ResponseWriter, r *http.Request) {
	purpose := r.URL.Query().Get("purpose")
	email := r.URL.Query().Get("subject_email")
	sinceStr := r.URL.Query().Get("since")
	if purpose == "" || email == "" || sinceStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "purpose, subject_email, and since query parameters are required")
		return
	}
	since, err := time.Parse(time.RFC3339Nano, sinceStr)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "since must be an RFC3339 timestamp")
		return
	}
	n, err := h.coreService.Storage().CountSetupTokensSince(r.Context(), purpose, email, since)
	if err != nil {
		log.Printf("setup-tokens proxy: count failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"count": n})
}
