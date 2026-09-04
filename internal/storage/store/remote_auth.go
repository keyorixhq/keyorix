// remote_auth.go — Session and Personal Access Token / Setup Token operations for
// RemoteStorage.
//
// Covers: CreateSession, GetSession, DeleteSession, CleanupExpiredSessions,
// personal access tokens (ADR-027), and setup tokens (ADR-028).
//
// For the local (GORM) equivalent see local_auth.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Sessions ---

// CreateSession deliberately has NO working remote implementation, and never
// will: a generic "persist this session" wire primitive — accepting an
// arbitrary UserID and minting a session for it — would be a confused-deputy /
// privilege-escalation oracle. Anyone holding the RemoteStorage service
// credential could mint a session for ANY user without ever proving that
// user's actual credentials, which is exactly the risk #508 was filed to
// avoid introducing. (It would also be silently broken in a different way:
// models.Session.SessionToken is tagged `json:"-"` specifically so a raw
// session can never cross the wire generically, so even a naive server route
// accepting this payload would receive an always-empty token.)
//
// Session issuance under storage.type: remote instead happens ATOMICALLY with
// credential verification, via VerifyLoginCredentials (remote_login_verify.go)
// — the upstream's own core.Login mints the session as part of the SAME call
// that proves the password correct, and returns its token directly. core.Login
// (internal/core/auth.go) uses that pre-minted session and never calls
// mintSession/CreateSession for a RemoteStorage-backed core.
//
// The two other mintSession call sites (MFA/WebAuthn login completion,
// internal/core/mfa.go; setup-token consume auto-login,
// internal/core/setup_consume.go) still reach this stub under
// storage.type: remote — both remain separately, pre-existingly unsupported
// there regardless of this function (MFA/WebAuthn: #509; setup tokens: #510),
// so failing loudly here is a strict improvement over a doomed 404 round-trip
// with no explanation.
func (rs *RemoteStorage) CreateSession(_ context.Context, _ *models.Session) (*models.Session, error) {
	return nil, remoteUnsupported("CreateSession")
}

// GetSession retrieves a session by token via remote API.
func (rs *RemoteStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	path := fmt.Sprintf("/api/v1/sessions/%s", url.PathEscape(token))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get session failed: %s", resp.Error.Error())
	}
	var result models.Session
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// DeleteSession deletes a session via remote API.
func (rs *RemoteStorage) DeleteSession(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/sessions/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete session failed: %s", resp.Error.Error())
	}
	return nil
}

// CleanupExpiredSessions: #1511/G80 deletion pass — POST
// /api/v1/sessions/cleanup has no matching route, and the core method itself
// has zero callers in any topology (internal/core/users.go's own doc comment
// already noted "implemented but never scheduled"). See
// docs/adr-087-remote-storage-deletion-pass.md.
func (rs *RemoteStorage) CleanupExpiredSessions(_ context.Context) error {
	return remoteUnsupported("CleanupExpiredSessions")
}

// --- Sessions (My Account) + Personal Access Tokens ---
//
// These methods exist to satisfy the Storage interface. Session validation and
// PAT auth run server-side against LocalStorage; the remote (CLI) client manages
// its own credentials over the public /api/v1/auth/* HTTP API directly, not
// through these storage methods. The server-only hot-path lookups therefore
// return errUnsupportedRemote, and the best-effort "touch" calls are no-ops.

var errUnsupportedRemote = fmt.Errorf("operation not supported over remote storage")

func (rs *RemoteStorage) GetSessionByID(_ context.Context, _ uint) (*models.Session, error) {
	return nil, remoteUnsupported("GetSessionByID")
}

func (rs *RemoteStorage) GetSessionAny(_ context.Context, _ string) (*models.Session, error) {
	return nil, remoteUnsupported("GetSessionAny")
}

func (rs *RemoteStorage) RotateSession(_ context.Context, _ uint, _ *models.Session, _ time.Time) (*models.Session, bool, error) {
	return nil, false, remoteUnsupported("RotateSession")
}

func (rs *RemoteStorage) ListSessionTokenHashesByFamily(_ context.Context, _ string) ([]string, error) {
	return nil, remoteUnsupported("ListSessionTokenHashesByFamily")
}

func (rs *RemoteStorage) DeleteSessionsByFamily(_ context.Context, _ string) error {
	return remoteUnsupported("DeleteSessionsByFamily")
}

func (rs *RemoteStorage) ListSessionsByUser(_ context.Context, _ uint) ([]*models.Session, error) {
	return nil, remoteUnsupported("ListSessionsByUser")
}

// deleteSessionsForUserExceptWire mirrors RemoteStorage's other small JSON
// request bodies (e.g. remote_mfa.go's markTOTPStepUsedWire) — a POST body
// rather than a DELETE-with-query-param, since HTTPClient.Delete takes no
// body and this call needs a second scalar (exceptSessionID) beyond the path
// parameter.
type deleteSessionsForUserExceptWire struct {
	ExceptSessionID uint `json:"except_session_id"`
}

// DeleteSessionsForUserExcept proxies to POST
// /api/v1/system/users/{id}/sessions/delete-except (G80 residual fix — see
// users_credentials_proxy.go for the server-side authority this closes).
func (rs *RemoteStorage) DeleteSessionsForUserExcept(ctx context.Context, userID, exceptSessionID uint) error {
	path := fmt.Sprintf("/api/v1/system/users/%d/sessions/delete-except", userID)
	resp, err := rs.client.Post(ctx, path, deleteSessionsForUserExceptWire{ExceptSessionID: exceptSessionID})
	if err != nil {
		return fmt.Errorf("failed to delete sessions for user: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete sessions for user failed: %s", resp.Error.Error())
	}
	return nil
}

func (rs *RemoteStorage) ListSessionTokenHashesForUser(_ context.Context, _ uint) ([]string, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) EnforceSessionLimit(_ context.Context, _ uint, _ int) error {
	return remoteUnsupported("EnforceSessionLimit")
}

func (rs *RemoteStorage) TouchSession(_ context.Context, _ uint, _ time.Time, _ time.Duration) error {
	return remoteUnsupported("TouchSession")
}

func (rs *RemoteStorage) CreatePersonalAccessToken(_ context.Context, _ *models.PersonalAccessToken) (*models.PersonalAccessToken, error) {
	return nil, remoteUnsupported("CreatePersonalAccessToken")
}

func (rs *RemoteStorage) ListPersonalAccessTokensByUser(_ context.Context, _ uint) ([]*models.PersonalAccessToken, error) {
	return nil, remoteUnsupported("ListPersonalAccessTokensByUser")
}

func (rs *RemoteStorage) ListActivePersonalAccessTokens(_ context.Context) ([]*models.PersonalAccessToken, error) {
	return nil, remoteUnsupported("ListActivePersonalAccessTokens")
}

func (rs *RemoteStorage) GetPersonalAccessTokenByID(_ context.Context, _ uint) (*models.PersonalAccessToken, error) {
	return nil, remoteUnsupported("GetPersonalAccessTokenByID")
}

func (rs *RemoteStorage) GetPersonalAccessTokenByHash(_ context.Context, _ string) (*models.PersonalAccessToken, error) {
	return nil, remoteUnsupported("GetPersonalAccessTokenByHash")
}

func (rs *RemoteStorage) RevokePersonalAccessToken(_ context.Context, _ uint) error {
	return remoteUnsupported("RevokePersonalAccessToken")
}

// revokeAllPersonalAccessTokensForUserResponse mirrors the {"hashes":[...]}
// shape RevokeAllPersonalAccessTokensForUserProxy returns — the caller needs
// the revoked hashes back to evict them from its own auth cache, exactly as
// the local (non-remote) RevokeAllPersonalAccessTokensForUser caller does
// (internal/core/users.go).
type revokeAllPersonalAccessTokensForUserResponse struct {
	Hashes []string `json:"hashes"`
}

// RevokeAllPersonalAccessTokensForUser proxies to POST
// /api/v1/system/users/{id}/personal-access-tokens/revoke-all (G80 residual
// fix — see users_credentials_proxy.go for the server-side authority this
// closes).
func (rs *RemoteStorage) RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error) {
	path := fmt.Sprintf("/api/v1/system/users/%d/personal-access-tokens/revoke-all", userID)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke personal access tokens for user: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("revoke personal access tokens for user failed: %s", resp.Error.Error())
	}
	var result revokeAllPersonalAccessTokensForUserResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Hashes, nil
}

func (rs *RemoteStorage) TouchPersonalAccessToken(_ context.Context, _ uint, _ time.Time, _ time.Duration) error {
	return remoteUnsupported("TouchPersonalAccessToken")
}

func (rs *RemoteStorage) ListExpiredPATsByUser(_ context.Context, _ uint, _ time.Time) ([]*models.PersonalAccessToken, error) {
	return nil, remoteUnsupported("ListExpiredPATsByUser")
}

func (rs *RemoteStorage) BulkRevokeExpiredPATsByUser(_ context.Context, _ uint, _ time.Time) ([]string, error) {
	return nil, remoteUnsupported("BulkRevokeExpiredPATsByUser")
}

// Setup Token Management (ADR-028, #510).
//
// A remote CLI client does not mint or consume setup tokens — but a DOWNSTREAM
// Keyorix SERVER booted with storage.type: remote (ADR-049) does: its own
// core.KeyorixCore issues and consumes setup tokens against ITS storage backend,
// which happens to be this RemoteStorage. Before #510 every method here was a hard
// stub, so CompleteSetup's very first step (inspectActiveSetupToken →
// GetSetupTokenByHash) failed unconditionally under storage.type: remote for EVERY
// setup-token purpose (account_setup, password_reset_link, invitation_accept), not
// just invitations.
//
// These are thin passthroughs onto six new routes under
// /api/v1/system/setup-tokens (server/http/handlers/setup_tokens_proxy.go),
// following the EXACT #507 pattern (remote_invitations.go): gated on the same
// broad system.read/system.write RBAC tier a RemoteStorage credential already
// needs for every other proxied call — no new privilege class — and making NO
// setup-token POLICY decision server-side (purpose validation, TTL, which
// transitions are legal). That all stays in the CALLING server's own
// internal/core.KeyorixCore (setup_token.go/setup_consume.go), exactly as it does
// against a local backend.
//
// Critically, MarkSetupTokenConsumed proxies onto local_auth.go's OWN
// `WHERE id = ? AND state = 'active'` conditional UPDATE — the single-use-consume
// guarantee consumeInspectedToken (setup_token.go) depends on to reject a
// concurrent replay. One HTTP round trip maps to one atomic server-side
// conditional UPDATE, not a client-side "GET, check state, then mark" sequence,
// which would reopen exactly that TOCTOU race.
func (rs *RemoteStorage) CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/setup-tokens", newSetupTokenWire(t))
	if err != nil {
		return nil, fmt.Errorf("failed to create setup token: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create setup token failed: %s", resp.Error.Error())
	}
	return decodeSetupTokenResponse(resp.Data)
}

// GetSetupTokenByHash is the consumption lookup (indexed equality on token_hash) via
// GET /api/v1/system/setup-tokens/by-hash/{hash}. The hash is a SHA-256 hex digest,
// never the raw plaintext token, and is path-escaped defensively like GetSession's
// bearer token above.
func (rs *RemoteStorage) GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error) {
	path := fmt.Sprintf("/api/v1/system/setup-tokens/by-hash/%s", url.PathEscape(hash))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get setup token: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get setup token failed: %s", resp.Error.Error())
	}
	return decodeSetupTokenResponse(resp.Data)
}

// GetSetupTokenByID has no RemoteStorage caller and no /system route: it only
// exists to resolve purpose/subject detail hub-side, inside
// KeyorixCore.ExpireSetupTokenByID (#1622), before its audit write --
// server/http/handlers is always LocalStorage-backed
// (validateRemoteStorageNotServer forbids the reverse), so this is genuinely
// unreachable in any deployment, matching MarkSetupTokenConsumed's own stub
// below.
func (rs *RemoteStorage) GetSetupTokenByID(_ context.Context, _ uint) (*models.SetupToken, error) {
	return nil, remoteUnsupported("GetSetupTokenByID")
}

// SupersedeActiveSetupTokens flips every active token for (purpose, email) to
// superseded via POST /api/v1/system/setup-tokens/supersede, preserving
// local_auth.go's exact semantics: a reissue kills the prior link atomically.
// projectID, when non-nil, is forwarded so the upstream server restricts the
// flip to that project's own invitations (CORE-INVITATIONS-003) — see
// local_auth.go's SupersedeActiveSetupTokens for the full rationale.
func (rs *RemoteStorage) SupersedeActiveSetupTokens(ctx context.Context, purpose, email string, projectID *uint) error {
	body := struct {
		Purpose      string `json:"purpose"`
		SubjectEmail string `json:"subject_email"`
		ProjectID    *uint  `json:"project_id,omitempty"`
	}{Purpose: purpose, SubjectEmail: email, ProjectID: projectID}
	resp, err := rs.client.Post(ctx, "/api/v1/system/setup-tokens/supersede", body)
	if err != nil {
		return fmt.Errorf("failed to supersede setup tokens: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("supersede setup tokens failed: %s", resp.Error.Error())
	}
	return nil
}

// MarkSetupTokenConsumed used to proxy onto POST
// /api/v1/system/setup-tokens/{id}/consume (ConsumeSetupTokenProxy), deleted
// in the #1579 liveness sweep: core.ConsumeSetupToken/consumeInspectedToken
// (internal/core/setup_token.go) is this method's only Go-level caller
// repo-wide, and its own only caller is server/http/handlers/auth.go's
// CompleteSetup — a human-facing HTTP route, unreachable from any process
// backed by this RemoteStorage (ADR-083: no server can boot with
// storage.type: remote). No CLI command calls ConsumeSetupToken/CompleteSetup
// either — completing account setup means providing a NEW password only the
// subject knows, which is inherently self-service, unlike the admin-driven
// account-lifecycle operations (deactivate, suspend, revoke) a CLI operator
// legitimately performs on another user's behalf. See
// docs/adr-090-stale-fork-proxy-deletion.md's "#1579/#1580" addendum for the
// full liveness trace and revival-hazard classification.
func (rs *RemoteStorage) MarkSetupTokenConsumed(_ context.Context, _ uint, _ time.Time) (bool, error) {
	return false, remoteUnsupported("MarkSetupTokenConsumed")
}

// MarkSetupTokenExpired transitions active → expired (lazy expiry on read) via
// POST /api/v1/system/setup-tokens/{id}/expire.
func (rs *RemoteStorage) MarkSetupTokenExpired(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/setup-tokens/%d/expire", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to expire setup token: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("expire setup token failed: %s", resp.Error.Error())
	}
	return nil
}

// CountSetupTokensSince counts tokens minted for (purpose, email) since a cutoff via
// GET /api/v1/system/setup-tokens/count, backing resend throttling and the daily cap.
func (rs *RemoteStorage) CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error) {
	q := url.Values{}
	q.Set("purpose", purpose)
	q.Set("subject_email", email)
	q.Set("since", since.UTC().Format(time.RFC3339Nano))
	path := "/api/v1/system/setup-tokens/count?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("failed to count setup tokens: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("count setup tokens failed: %s", resp.Error.Error())
	}
	var result struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Count, nil
}

// setupTokenWire mirrors models.SetupToken's fields exactly (snake_case), used for
// both the create-request body and every response (create/get), for the same
// reason invitationWire (remote_invitations.go) does: models.SetupToken is a GORM
// model with no json tags of its own (besides TokenHash's `json:"-"`, which exists
// to keep the hash out of any USER-facing response — irrelevant here, since this is
// an internal system-to-system wire format gated on system.read/system.write, the
// same tier that already round-trips full user/secret/invitation records).
type setupTokenWire struct {
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

// newSetupTokenWire builds the CreateSetupToken request body. Every timestamp is
// UTC-normalized: CountSetupTokensSince's `since` query parameter is always sent
// UTC-converted (see that method below), and the upstream's LocalStorage backend
// (SQLite) compares these columns as plain TEXT, not real chronological values —
// a CreatedAt/ExpiresAt persisted with the calling server's local offset (whatever
// core.KeyorixCore.now() returns there) would sort incorrectly against a
// UTC-formatted comparison threshold. Normalizing here keeps every setup-token
// timestamp that crosses this wire directly, lexicographically comparable.
func newSetupTokenWire(t *models.SetupToken) setupTokenWire {
	var consumedAt *time.Time
	if t.ConsumedAt != nil {
		utc := t.ConsumedAt.UTC()
		consumedAt = &utc
	}
	return setupTokenWire{
		ID:            t.ID,
		TokenHash:     t.TokenHash,
		Purpose:       t.Purpose,
		SubjectUserID: t.SubjectUserID,
		SubjectEmail:  t.SubjectEmail,
		InvitationID:  t.InvitationID,
		State:         t.State,
		ExpiresAt:     t.ExpiresAt.UTC(),
		CreatedBy:     t.CreatedBy,
		CreatedAt:     t.CreatedAt.UTC(),
		ConsumedAt:    consumedAt,
	}
}

func (w setupTokenWire) toModel() *models.SetupToken {
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

func decodeSetupTokenResponse(data []byte) (*models.SetupToken, error) {
	var wire setupTokenWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}
