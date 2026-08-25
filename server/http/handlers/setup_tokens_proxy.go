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
// One exception: CreateSetupTokenProxy is NOT a thin passthrough — see its own
// doc comment. Minting a setup token for user X is equivalent to taking
// control of X, so it now requires the SAME users.write authority every other
// admin-facing route that mints one already requires (POST /api/v1/users,
// POST /api/v1/users/{id}/resend-setup-link), for every caller.
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
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
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

// validSetupTokenProxyPurposes mirrors internal/core/setup_token.go's unexported
// validSetupPurpose — duplicated here (a small, stable enum) because this proxy
// cannot import internal/core's unexported validator. Kept as the authoritative
// list CreateSetupTokenProxy checks the wire body's Purpose against.
var validSetupTokenProxyPurposes = map[string]bool{
	"invitation_accept":   true,
	"account_setup":       true,
	"password_reset_link": true,
}

// maxSetupTokenProxyTTL bounds how far in the future a proxied setup token's
// ExpiresAt may be, independent of whatever core.DefaultSetupTokenTTL (24h) the
// calling server is configured with — a generous ceiling, not the real policy,
// since this proxy has no visibility into the calling server's actual TTL
// setting; it exists only to reject an unbounded/absurd expiry.
const maxSetupTokenProxyTTL = 30 * 24 * time.Hour

// CreateSetupTokenProxy handles POST /api/v1/system/setup-tokens. The caller (the
// downstream server's own core.KeyorixCore.IssueSetupToken) has already computed
// every field — the hash, purpose, TTL, subject — exactly as it would for
// LocalStorage; this is otherwise a raw persist, no POLICY decision (which fields
// a real IssueSetupToken call would compute).
//
// #G79: token_hash is, by design, always caller-supplied — the raw token is
// generated with crypto/rand on whichever node calls IssueSetupToken (local or
// remote), and only its hash ever crosses this wire; there is no way to
// regenerate or independently verify it here without defeating the entire
// point of hashing (the plaintext must never reach this layer). The
// invitation/user cross-reference check below ties the token to a real,
// already-vetted record — but it only enforces INTERNAL CONSISTENCY between
// the caller-supplied fields, never caller AUTHORITY to target the account
// those fields name.
//
// G80 documented-exception re-verification sweep (2026-08-25): confirmed
// exploitable as a result. Every human-facing operation that mints a setup
// token for an admin-CHOSEN target requires users.write elsewhere in this
// codebase -- POST /api/v1/users (CreateUser -> CreateUserWithSetupLink/
// CreateUserWithOneTimePassword, router.go, RequirePermission(permUsersWrite))
// and POST /api/v1/users/{id}/resend-setup-link (ResendSetupLink ->
// ResendAccountSetupLink, same gate) -- but this route's own gate was only
// system.write, a narrower-scoped permission per auth_bootstrap.go's own
// documented footprint (audit checkpoints/legal holds/risk exceptions/SoD
// policies, not user credential control). A caller holding only system.write
// who already knew (or guessed) a real target's email/user-ID could mint a
// fully-valid, immediately-redeemable takeover token for that target via the
// public, unauthenticated POST /auth/setup/consume -- overwriting the
// target's real password and, for a non-MFA account, receiving a live
// session AS them.
//
// Rejected fix: narrowing this route to the node-credential arm only. Two
// reasons. First, that reasoning is the SAME "the package doc says so" class
// of claim this sweep already disproved 3 times elsewhere (verify, don't
// trust the doc) -- and liveness-checking it here confirms the opposite: a
// node-credential relay of THIS specific route is real and load-bearing
// (RemoteStorage.CreateSetupToken, internal/storage/store/remote_auth.go:211,
// is a genuine implementation invoked by ordinary product flows -- every
// project invite, every admin "create user"/"resend setup link" action, the
// self-service forgot-password flow -- not dead code). Second, and more
// important: per #1552, a bare node credential could already be used to
// grant ANY role including admin-tier before ADR-085 -- it is the single
// most widely distributed credential class in a deployment, not a stronger
// boundary than system.write. Narrowing an account-takeover primitive to
// node-credential-only would have LOWERED the effective bar, not raised it.
//
// Fixed by deriving the ceiling from the operation itself: every caller must
// hold users.write (global scope, matching the human-facing routes above)
// before this handler persists a token. This check now runs unconditionally
// for every caller. It used to be skipped for a genuine node-credential relay
// -- ADR-085 (Accepted, 2026-08-25) found that "downstream node relay"
// topology cannot exist in this codebase (ADR-083's
// validateRemoteStorageNotServer rejects storage.type: remote for any server
// process) and removed the exemption.
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
	if !validSetupTokenProxyPurposes[body.Purpose] {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "unknown setup-token purpose")
		return
	}
	if body.ExpiresAt.After(time.Now().Add(maxSetupTokenProxyTTL)) {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "expires_at is too far in the future")
		return
	}
	subjectEmail := strings.ToLower(strings.TrimSpace(body.SubjectEmail))
	if body.Purpose == "invitation_accept" {
		if body.InvitationID == nil || body.SubjectUserID != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invitation_accept requires invitation_id and no subject_user_id")
			return
		}
		inv, err := h.coreService.Storage().GetProjectInvitation(r.Context(), *body.InvitationID)
		if err != nil || !strings.EqualFold(strings.TrimSpace(inv.Email), subjectEmail) {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invitation_id does not reference a matching invitation")
			return
		}
	} else {
		if body.SubjectUserID == nil || body.InvitationID != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "this purpose requires subject_user_id and no invitation_id")
			return
		}
		user, err := h.coreService.Storage().GetUser(r.Context(), *body.SubjectUserID)
		if err != nil || !strings.EqualFold(strings.TrimSpace(user.Email), subjectEmail) {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "subject_user_id does not reference a matching user")
			return
		}
	}
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "minting a setup token requires the users.write permission")
		return
	}
	if ok, aerr := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "users.write", coreStorage.Scope{}); aerr != nil || !ok {
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "minting a setup token requires the users.write permission")
		return
	}
	// G80 documented-exception re-verification sweep (2026-08-25): CreatedBy
	// used to persist verbatim from the wire and feed the setup_token.issued
	// audit event's actor field. This route's own gating decision (users.write
	// above) was already correctly context-derived; force provenance to match.
	model := body.toModel()
	model.CreatedBy = userCtx.PrincipalID()
	created, err := h.coreService.Storage().CreateSetupToken(r.Context(), model)
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
// /api/v1/system/setup-tokens/supersede. ProjectID is optional (omitted/nil for
// callers with no project dimension — global invites, account_setup,
// password_reset_link); when present it restricts the flip to that project's own
// invitations (CORE-INVITATIONS-003).
type setupTokenSupersedeBody struct {
	Purpose      string `json:"purpose"`
	SubjectEmail string `json:"subject_email"`
	ProjectID    *uint  `json:"project_id,omitempty"`
}

// SupersedeSetupTokensProxy handles POST /api/v1/system/setup-tokens/supersede. It
// performs the SAME `WHERE purpose = ? AND subject_email = ? AND state = 'active'`
// bulk UPDATE (optionally further restricted to ProjectID's own invitations)
// local_auth.go's own SupersedeActiveSetupTokens does — a reissue kills every prior
// active link for the same (purpose, email[, project]) atomically.
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
	if err := h.coreService.Storage().SupersedeActiveSetupTokens(r.Context(), body.Purpose, body.SubjectEmail, body.ProjectID); err != nil {
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
