// remote_webauthn.go — WebAuthn / passkey storage primitives for RemoteStorage
// (ADR-036/ADR-049, finding #517): thin CRUD passthroughs onto new server-side
// routes under /api/v1/system/webauthn (server/http/handlers/webauthn_proxy.go),
// gated on the SAME broad system.read/system.write RBAC permissions a
// RemoteStorage credential already needs for every other proxied call (dynamic
// secrets, groups, project memberships, setup tokens, invitations, login
// attempts) — so this introduces no new privilege class.
//
// Unlike remote_mfa.go's TOTP methods (IssueMFAChallenge/VerifyMFALoginCredentials,
// a verification PROXY: the raw TOTP secret must never leave the server that can
// decrypt it, so the entire check runs upstream), WebAuthn's registered-credential
// public key and its in-flight ceremony session state are not secret — a spoke
// server that holds a credential row can verify an assertion against it entirely
// locally, with no need for the upstream server to do any cryptography on its
// behalf. So every method here is an ordinary storage-primitive passthrough (no
// WebAuthn ceremony/ownership/reauth POLICY decision is made in these routes —
// that stays entirely in the CALLING server's own internal/core.KeyorixCore,
// exactly as it does against a local backend), matching the Groups/Dynamic-Secrets
// precedent (remote_groups.go/remote_dynamic.go) rather than the MFA one.
//
// The signature-counter race (#306/#517): AdvanceWebAuthnCredentialCounter is the
// ONE method here that is NOT a plain CRUD passthrough. LockWebAuthnCredentialForUpdate
// + UpdateWebAuthnCredential remain ordinary (independent, non-atomic) proxies —
// fine for a plain read or rejectIfCloned's best-effort "mark disabled" write, whose
// worst outcome under a lost race is a harmless redundant write. But
// persistUpdatedCredential's read-validate-write of the advanced sign counter
// (internal/core/webauthn.go) MUST be atomic: RemoteStorage.WithTransaction is a
// no-op passthrough (remote_transaction.go — each remote call is independent), so
// composing a plain GET (Lock) and a plain PUT (Update) as two separate remote
// calls would reopen the exact TOCTOU race a local transaction's row lock exists to
// close — two concurrent logins could both GET the stale counter, both pass their
// local staleness check, and the loser's PUT could stomp the winner's
// already-persisted higher counter, silently defeating clone detection. Instead,
// AdvanceWebAuthnCredentialCounter is ONE PATCH call whose server-side handler runs
// the identical locked compare-and-swap against its OWN storage inside that single
// request — the real atomicity is achieved server-side in one round trip, not
// client-side across several.
//
// For the local (GORM) equivalent of every primitive here see local_webauthn.go.
package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// webAuthnCredentialWire mirrors webAuthnCredentialProxyWire in
// server/http/handlers/webauthn_proxy.go exactly. models.WebAuthnCredential carries
// no json tags of its own, so every field is named explicitly rather than relying
// on encoding/json's case-insensitive fallback (matching every other proxy wire
// type in this package, e.g. dynamicSecretConfigWire).
type webAuthnCredentialWire struct {
	ID             uint       `json:"id"`
	UserID         uint       `json:"user_id"`
	CredentialID   []byte     `json:"credential_id"`
	Name           string     `json:"name"`
	CredentialBlob []byte     `json:"credential_blob"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	Disabled       bool       `json:"disabled"`
}

func newWebAuthnCredentialWire(c *models.WebAuthnCredential) webAuthnCredentialWire {
	return webAuthnCredentialWire{
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

func (w webAuthnCredentialWire) toModel() *models.WebAuthnCredential {
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

func decodeWebAuthnCredentialResponse(data []byte) (*models.WebAuthnCredential, error) {
	var wire webAuthnCredentialWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// webAuthnSessionWire mirrors webAuthnSessionProxyWire exactly. TokenHash is
// tagged `json:"-"` on models.WebAuthnSession (to keep it out of USER-facing
// responses) — irrelevant here, since this is an internal system-to-system wire
// format gated on system.read/system.write, matching setupTokenWire's identical
// TokenHash precedent (remote_auth.go).
type webAuthnSessionWire struct {
	ID        uint       `json:"id"`
	UserID    uint       `json:"user_id"`
	TokenHash string     `json:"token_hash"`
	Purpose   string     `json:"purpose"`
	Data      []byte     `json:"data"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func newWebAuthnSessionWire(s *models.WebAuthnSession) webAuthnSessionWire {
	return webAuthnSessionWire{
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

func (w webAuthnSessionWire) toModel() *models.WebAuthnSession {
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

func decodeWebAuthnSessionResponse(data []byte) (*models.WebAuthnSession, error) {
	var wire webAuthnSessionWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// webAuthnCredentialIDQuery base64-encodes a raw (binary) credential ID for use as
// a URL query value — the same encoding encoding/json already uses for a []byte
// field, so this is the least surprising choice, and net/url's Encode
// percent-escapes whatever the base64 alphabet produces, so no character is
// URL-unsafe in the resulting query string.
func webAuthnCredentialIDQuery(credentialID []byte) string {
	return base64.StdEncoding.EncodeToString(credentialID)
}

// CreateWebAuthnCredential used to proxy onto POST
// /api/v1/system/webauthn/credentials (CreateWebAuthnCredentialProxy), deleted
// in the G80 liveness sweep — no live caller in either topology; see
// docs/g80-remediation-notes.md. Returns errUnsupportedRemote like every other
// known-unsupported RemoteStorage operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) CreateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return remoteUnsupported("CreateWebAuthnCredential")
}

// ListWebAuthnCredentials lists a user's registered passkeys via GET
// /api/v1/system/webauthn/credentials?user_id=X.
func (rs *RemoteStorage) ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error) {
	q := url.Values{}
	q.Set("user_id", strconv.FormatUint(uint64(userID), 10))
	path := "/api/v1/system/webauthn/credentials?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list webauthn credentials: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list webauthn credentials failed: %s", resp.Error.Error())
	}
	var result struct {
		Credentials []webAuthnCredentialWire `json:"credentials"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.WebAuthnCredential, 0, len(result.Credentials))
	for _, w := range result.Credentials {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// GetWebAuthnCredentialByCredID looks up a credential by (credential_id, user_id)
// via GET /api/v1/system/webauthn/credentials/lookup?user_id=&credential_id=
// (base64). The query itself requires user_id, so this preserves the local
// implementation's ownership scoping (#307): a caller cannot fetch another user's
// credential blob by omitting or forgetting the check.
func (rs *RemoteStorage) GetWebAuthnCredentialByCredID(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error) {
	q := url.Values{}
	q.Set("user_id", strconv.FormatUint(uint64(userID), 10))
	q.Set("credential_id", webAuthnCredentialIDQuery(credentialID))
	path := "/api/v1/system/webauthn/credentials/lookup?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get webauthn credential: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get webauthn credential failed: %s", resp.Error.Error())
	}
	return decodeWebAuthnCredentialResponse(resp.Data)
}

// LockWebAuthnCredentialForUpdate is, over the wire, the SAME plain (uncached-by-
// this-package, but see HTTPClient.Get's own 5-minute GET cache — an existing,
// pre-#517 tradeoff shared by every other proxied read in this package, e.g.
// ListDynamicSecretConfigs) read as GetWebAuthnCredentialByCredID: there is no
// row lock that could usefully persist across a single, standalone HTTP request
// with no further statement to serialize against. That's fine — the ONE caller
// that used to need this method's lock for correctness, persistUpdatedCredential's
// signature-counter advance, now calls AdvanceWebAuthnCredentialCounter below
// instead, which achieves real atomicity in one call. This method remains for
// interface conformance and any caller that just wants the current row (a locked
// read is a strict superset of a plain one).
func (rs *RemoteStorage) LockWebAuthnCredentialForUpdate(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error) {
	return rs.GetWebAuthnCredentialByCredID(ctx, credentialID, userID)
}

// UpdateWebAuthnCredential persists the full credential row via PUT
// /api/v1/system/webauthn/credentials/{id} — an unconditional full-row Save,
// matching LocalStorage's own semantics exactly. Used by rejectIfCloned's
// best-effort "mark disabled" write (internal/core/webauthn.go); the
// signature-counter advance path does NOT use this method — see
// AdvanceWebAuthnCredentialCounter.
func (rs *RemoteStorage) UpdateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error {
	path := fmt.Sprintf("/api/v1/system/webauthn/credentials/%d", c.ID)
	resp, err := rs.client.Put(ctx, path, newWebAuthnCredentialWire(c))
	if err != nil {
		return fmt.Errorf("failed to update webauthn credential: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update webauthn credential failed: %s", resp.Error.Error())
	}
	return nil
}

// advanceWebAuthnCounterWire is the wire body for
// AdvanceWebAuthnCredentialCounterProxy — see that method's doc
// (internal/core/storage/interface.go) for the full contract.
type advanceWebAuthnCounterWire struct {
	CredentialID []byte    `json:"credential_id"`
	UserID       uint      `json:"user_id"`
	NewBlob      []byte    `json:"new_blob"`
	NewSignCount uint32    `json:"new_sign_count"`
	LastUsedAt   time.Time `json:"last_used_at"`
}

// AdvanceWebAuthnCredentialCounter is the ONE non-plain-CRUD method in this file:
// see the package doc above and the storage.Storage interface doc for why the
// signature-counter advance needs a single atomic PATCH
// (/api/v1/system/webauthn/credentials/advance-counter) rather than a
// Lock-then-Update pair. Deliberately bypasses rs.client.Get's cache (it is a
// PATCH, not a GET) — the security-critical compare-and-swap must always hit the
// upstream server fresh, never a stale cached response.
func (rs *RemoteStorage) AdvanceWebAuthnCredentialCounter(ctx context.Context, credentialID []byte, userID uint, newBlob []byte, newSignCount uint32, lastUsedAt time.Time) (bool, error) {
	resp, err := rs.client.Request(ctx, http.MethodPatch, "/api/v1/system/webauthn/credentials/advance-counter", advanceWebAuthnCounterWire{
		CredentialID: credentialID,
		UserID:       userID,
		NewBlob:      newBlob,
		NewSignCount: newSignCount,
		LastUsedAt:   lastUsedAt,
	})
	if err != nil {
		return false, fmt.Errorf("failed to advance webauthn credential counter: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("advance webauthn credential counter failed: %s", resp.Error.Error())
	}
	var result struct {
		Advanced bool `json:"advanced"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Advanced, nil
}

// DeleteWebAuthnCredential used to proxy onto DELETE
// /api/v1/system/webauthn/users/{userID}/credentials/{id}
// (DeleteWebAuthnCredentialProxy), deleted in the G80 liveness sweep — no live
// caller in either topology; see docs/g80-remediation-notes.md. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) DeleteWebAuthnCredential(_ context.Context, _, _ uint) error {
	return remoteUnsupported("DeleteWebAuthnCredential")
}

// CountWebAuthnCredentials returns a user's registered-passkey count via GET
// /api/v1/system/webauthn/credentials/count?user_id=X.
func (rs *RemoteStorage) CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error) {
	q := url.Values{}
	q.Set("user_id", strconv.FormatUint(uint64(userID), 10))
	path := "/api/v1/system/webauthn/credentials/count?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("failed to count webauthn credentials: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("count webauthn credentials failed: %s", resp.Error.Error())
	}
	var result struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Count, nil
}

// SetUserWebAuthnEnabled used to proxy onto PUT
// /api/v1/system/webauthn/users/{userID}/webauthn-enabled
// (SetUserWebAuthnEnabledProxy), deleted in the G80 liveness sweep — no live
// caller in either topology; see docs/g80-remediation-notes.md. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) SetUserWebAuthnEnabled(_ context.Context, _ uint, _ bool) error {
	return remoteUnsupported("SetUserWebAuthnEnabled")
}

// CreateWebAuthnSession persists a new ceremony session via POST
// /api/v1/system/webauthn/sessions, then copies the upstream-assigned fields (ID,
// CreatedAt) back into s — mirroring CreateWebAuthnCredential's same in-place-mutate
// contract.
func (rs *RemoteStorage) CreateWebAuthnSession(ctx context.Context, s *models.WebAuthnSession) error {
	resp, err := rs.client.Post(ctx, "/api/v1/system/webauthn/sessions", newWebAuthnSessionWire(s))
	if err != nil {
		return fmt.Errorf("failed to create webauthn session: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("create webauthn session failed: %s", resp.Error.Error())
	}
	created, err := decodeWebAuthnSessionResponse(resp.Data)
	if err != nil {
		return err
	}
	*s = *created
	return nil
}

// webAuthnSessionConsumeWire is the wire body for ConsumeWebAuthnSessionProxy.
// It no longer carries `now` on the wire (G-wave6, same fix as
// remote_mfa.go's mfaChallengeLookupWire): the upstream server always uses
// its own clock for the expiry comparison instead of trusting a
// caller-supplied value.
type webAuthnSessionConsumeWire struct {
	TokenHash string `json:"token_hash"`
}

// ConsumeWebAuthnSession atomically marks a valid (unused, unexpired) ceremony
// session used and returns it, via POST /api/v1/system/webauthn/sessions/consume.
// The atomicity guarantee is unchanged from LocalStorage's own implementation
// (an UPDATE ... WHERE used_at IS NULL AND expires_at > ?): the proxy handler calls
// storage.ConsumeWebAuthnSession directly against the upstream's real storage in
// this single request, so the single-use invariant holds across this HTTP hop too
// (mirroring MarkSetupTokenConsumed's #510 precedent exactly). Every failure —
// missing/already-used/expired token, or a network/parse error — collapses to the
// same generic error, mirroring VerifyMFALoginCredentials' error-collapsing above:
// the caller (internal/core.FinishWebAuthnRegistration/FinishWebAuthnLogin) already
// treats any error here as "invalid or expired registration/login session"
// regardless of cause.
// now is accepted only for interface parity with LocalStorage — the
// upstream server ignores any caller-supplied "current time" and always
// uses its own clock (see webAuthnSessionConsumeWire's doc comment).
func (rs *RemoteStorage) ConsumeWebAuthnSession(ctx context.Context, tokenHash string, _ time.Time) (*models.WebAuthnSession, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/webauthn/sessions/consume", webAuthnSessionConsumeWire{
		TokenHash: tokenHash,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid or expired webauthn session")
	}
	if !resp.Success {
		return nil, fmt.Errorf("invalid or expired webauthn session")
	}
	return decodeWebAuthnSessionResponse(resp.Data)
}
