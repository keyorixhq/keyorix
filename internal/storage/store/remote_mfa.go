// remote_mfa.go — MFA persistence for RemoteStorage: the login-verification
// half (IssueMFAChallenge/VerifyMFALoginCredentials, below) and the
// enrolment/management half (UpsertMFASecret..DeleteMFARecoveryCodes, also
// below, finding #524) are two DIFFERENT proxy shapes for two different
// problems — see each section's doc for why.
//
// IssueMFAChallenge and VerifyMFALoginCredentials below implement
// core.RemoteMFAVerifier (#509): the upstream half of the storage.type: remote
// TOTP second-factor LOGIN proxy, mirroring remote_login_verify.go's password
// proxy (#506) exactly. Login verification must run entirely upstream because
// VerifyMFACredentials (internal/core/mfa.go) needs to compare a caller-supplied
// code against the DECRYPTED secret, and account lockout accounting has to be
// serialized with the password-step lockout check — a wire-DTO passthrough of
// the storage primitives alone would still leave that whole check unreachable
// on a spoke node.
//
// UpsertMFASecret/GetMFASecret/ActivateMFASecret/DeleteMFAForUser/
// SetUserMFAEnabled/CreateMFARecoveryCodes/CountUnusedMFARecoveryCodes/
// DeleteMFARecoveryCodes below are a DIFFERENT, CRUD-shaped problem
// (finding #524): enrolment (BeginMFAEnrollment/ActivateMFA) and management
// (DisableMFA/RegenerateMFARecoveryCodes/MFARecoveryCodesRemaining,
// internal/core/mfa.go) ALWAYS run on whichever server terminates the
// end-user's /auth/mfa/* request — never delegated to a RemoteMFAVerifier —
// so before this fix these eight methods being unconditional stubs made MFA
// enrolment and management 100% broken under storage.type: remote (login
// itself, once already-active, was unaffected: it goes through the
// RemotMFAVerifier proxy above). These are thin passthroughs onto new routes
// under /api/v1/system/mfa (server/http/handlers/mfa_management_proxy.go),
// gated on the SAME system.read/system.write RBAC tier every other
// RemoteStorage proxy call already uses — no new privilege class. No MFA
// POLICY decision (re-auth gate, single-active-method enforcement, recovery
// code generation/hashing, session invalidation on activation) is made in
// these routes; that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend.
//
// Sensitive-data boundary (investigated, not assumed — mirrors
// remote_dynamic.go's identical AdminDSN/Credential boundary exactly):
// MFASecret.SecretEnc/SecretMeta is encrypted by internal/core
// (KeyorixCore.encryptAuthSecret/decryptAuthSecret) using the CALLING
// server's own encryption key BEFORE the row is ever handed to
// UpsertMFASecret, and decrypted only after GetMFASecret returns it — never in
// plaintext, and never by the upstream server these routes live on. The wire
// type below carries SecretEnc/SecretMeta as opaque ciphertext bytes; the
// upstream's proxy handlers never decrypt it. (BeginMFAEnrollment also
// refuses outright when at-rest encryption is disabled — see
// models.MFASecret's own doc — so this ciphertext is never actually plaintext
// even in that degraded case.)
//
// Atomicity (checked against local_mfa.go, not assumed): every one of these
// eight methods is ALREADY a single storage.Storage call in
// internal/core/mfa.go — none of ActivateMFA/DisableMFA/
// RegenerateMFARecoveryCodes wraps its several storage calls in
// core.storage.WithTransaction (RemoteStorage.WithTransaction is a no-op
// passthrough anyway, remote_transaction.go), and DeleteMFAForUser's OWN
// internal secret+recovery-codes delete already happens inside ONE local GORM
// transaction wholly inside local_mfa.go, not split across two core-level
// calls. So proxying each of these eight as ONE HTTP round trip to the
// upstream (which still executes local_mfa.go's own UPDATE/transaction
// server-side) preserves whatever atomicity the local backend already had —
// unlike AdvanceWebAuthnCredentialCounter (#517) or
// CreateSecretDependencyExclusive (#519), no NEW combined atomic primitive is
// needed here, because no caller here composes a Lock-then-Update (or
// check-then-act) pair across two SEPARATE storage calls that this HTTP hop
// could reopen a race in.
//
// GetActiveMFAChallenge and ConsumeMFAChallenge below are DIFFERENT again:
// they are ordinary storage.Storage passthroughs (#522), not part of the
// RemoteMFAVerifier proxy. models.MFAChallenge is a SHARED pre-auth token: the
// SAME row backs both the TOTP path (proxied wholesale above, since it also
// needs the encrypted secret) and WebAuthn-as-second-factor login
// (internal/core/webauthn.go's BeginWebAuthnLogin/FinishWebAuthnLogin), which has
// no secret of its own to protect — a spoke server that resolves the
// challenge's user_id can run the entire passkey assertion ceremony locally
// against its own (already-proxied, #517) WebAuthn credential rows.
//
// WebAuthn's OWN storage.Storage primitives (registered credentials, ceremony
// sessions) are handled separately: see remote_webauthn.go / #517.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// mfaSecretWire mirrors models.MFASecret's fields exactly (snake_case).
// SecretEnc/SecretMeta/LastUsedStep are tagged json:"-" on the model (to keep
// them out of USER-facing responses) — irrelevant here, since this is an
// internal system-to-system wire format gated on system.read/system.write,
// matching webAuthnSessionWire's identical json:"-"-field precedent. SecretEnc/
// SecretMeta carry the CALLING server's own ciphertext verbatim — see this
// file's package doc for why that is safe to transmit as opaque bytes.
type mfaSecretWire struct {
	ID           uint      `json:"id"`
	UserID       uint      `json:"user_id"`
	SecretEnc    []byte    `json:"secret_enc"`
	SecretMeta   []byte    `json:"secret_meta"`
	Activated    bool      `json:"activated"`
	LastUsedStep *int64    `json:"last_used_step"`
	CreatedAt    time.Time `json:"created_at"`
}

func newMFASecretWire(s *models.MFASecret) mfaSecretWire {
	return mfaSecretWire{
		ID:           s.ID,
		UserID:       s.UserID,
		SecretEnc:    s.SecretEnc,
		SecretMeta:   s.SecretMeta,
		Activated:    s.Activated,
		LastUsedStep: s.LastUsedStep,
		CreatedAt:    s.CreatedAt,
	}
}

func (w mfaSecretWire) toModel() *models.MFASecret {
	return &models.MFASecret{
		ID:           w.ID,
		UserID:       w.UserID,
		SecretEnc:    w.SecretEnc,
		SecretMeta:   w.SecretMeta,
		Activated:    w.Activated,
		LastUsedStep: w.LastUsedStep,
		CreatedAt:    w.CreatedAt,
	}
}

func decodeMFASecretResponse(data []byte) (*models.MFASecret, error) {
	var wire mfaSecretWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// UpsertMFASecret persists the user's TOTP secret row via POST
// /api/v1/system/mfa/secrets, then copies the upstream-assigned fields (ID,
// CreatedAt) back into s — mirroring CreateWebAuthnCredential's identical
// in-place-mutate contract, and LocalStorage's own GORM Create-with-OnConflict,
// which does the same.
func (rs *RemoteStorage) UpsertMFASecret(ctx context.Context, s *models.MFASecret) error {
	resp, err := rs.client.Post(ctx, "/api/v1/system/mfa/secrets", newMFASecretWire(s))
	if err != nil {
		return fmt.Errorf("failed to store MFA secret: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("store MFA secret failed: %s", resp.Error.Error())
	}
	saved, err := decodeMFASecretResponse(resp.Data)
	if err != nil {
		return err
	}
	*s = *saved
	return nil
}

// GetMFASecret fetches a user's TOTP secret row via GET
// /api/v1/system/mfa/secrets?user_id=X — the CALLING server then decrypts
// SecretEnc/SecretMeta with its own key (loadTOTPSecret,
// internal/core/mfa.go), exactly as it would against a local backend.
func (rs *RemoteStorage) GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error) {
	q := url.Values{}
	q.Set("user_id", strconv.FormatUint(uint64(userID), 10))
	path := "/api/v1/system/mfa/secrets?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA secret: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get MFA secret failed: %s", resp.Error.Error())
	}
	return decodeMFASecretResponse(resp.Data)
}

// ActivateMFASecret marks the user's pending TOTP secret activated via POST
// /api/v1/system/mfa/secrets/{userId}/activate — an unconditional single-column
// UPDATE, matching LocalStorage's own semantics exactly (no WHERE-activated
// guard locally either; ActivateMFA's password/TOTP re-auth is the only gate).
func (rs *RemoteStorage) ActivateMFASecret(ctx context.Context, userID uint) error {
	path := fmt.Sprintf("/api/v1/system/mfa/secrets/%d/activate", userID)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to activate MFA secret: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("activate MFA secret failed: %s", resp.Error.Error())
	}
	return nil
}

// markTOTPStepUsedWire mirrors MarkTOTPStepUsedProxy's request body.
type markTOTPStepUsedWire struct {
	UserID uint  `json:"user_id"`
	Step   int64 `json:"step"`
}

// markTOTPStepUsedResponse mirrors MarkTOTPStepUsedProxy's data envelope.
type markTOTPStepUsedResponse struct {
	Fresh bool `json:"fresh"`
}

// MarkTOTPStepUsed atomically advances the per-user last-used TOTP step via
// POST /api/v1/system/mfa/totp-step-used, so requireReauth and
// VerifyMFACredentials anti-replay work correctly under storage.type: remote.
func (rs *RemoteStorage) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/mfa/totp-step-used", markTOTPStepUsedWire{UserID: userID, Step: step})
	if err != nil {
		return false, fmt.Errorf("failed to mark TOTP step used: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("mark TOTP step used failed: %s", resp.Error.Error())
	}
	var result markTOTPStepUsedResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse mark TOTP step used response: %w", err)
	}
	return result.Fresh, nil
}

// DeleteMFAForUser clears a user's secret and all recovery codes via DELETE
// /api/v1/system/mfa/users/{userId} — ONE HTTP round trip onto the upstream's
// own DeleteMFAForUser, so this inherits local_mfa.go's internal
// secret-then-codes GORM transaction unchanged; there is no separate
// "delete secret, then delete codes" sequence here to reopen a partial-delete
// gap across the HTTP hop.
func (rs *RemoteStorage) DeleteMFAForUser(ctx context.Context, userID uint) error {
	path := fmt.Sprintf("/api/v1/system/mfa/users/%d", userID)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete MFA for user: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete MFA for user failed: %s", resp.Error.Error())
	}
	return nil
}

// setUserMFAEnabledWire is the wire body for SetUserMFAEnabledProxy, mirroring
// setUserWebAuthnEnabledWire exactly.
type setUserMFAEnabledWire struct {
	Enabled bool `json:"enabled"`
}

// SetUserMFAEnabled flips the user's MFAEnabled flag via PUT
// /api/v1/system/mfa/users/{userId}/mfa-enabled.
func (rs *RemoteStorage) SetUserMFAEnabled(ctx context.Context, userID uint, enabled bool) error {
	path := fmt.Sprintf("/api/v1/system/mfa/users/%d/mfa-enabled", userID)
	resp, err := rs.client.Put(ctx, path, setUserMFAEnabledWire{Enabled: enabled})
	if err != nil {
		return fmt.Errorf("failed to set MFA enabled: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("set MFA enabled failed: %s", resp.Error.Error())
	}
	return nil
}

// createMFARecoveryCodesWire is the wire body for CreateMFARecoveryCodesProxy.
type createMFARecoveryCodesWire struct {
	CodeHashes []string `json:"code_hashes"`
}

// CreateMFARecoveryCodes bulk-inserts the user's hashed recovery codes via
// POST /api/v1/system/mfa/recovery-codes. The plaintext codes themselves never
// cross the wire — ActivateMFA/RegenerateMFARecoveryCodes
// (internal/core/mfa.go) hash them locally first, exactly as they do against a
// local backend.
func (rs *RemoteStorage) CreateMFARecoveryCodes(ctx context.Context, userID uint, codeHashes []string) error {
	path := fmt.Sprintf("/api/v1/system/mfa/recovery-codes?user_id=%d", userID)
	resp, err := rs.client.Post(ctx, path, createMFARecoveryCodesWire{CodeHashes: codeHashes})
	if err != nil {
		return fmt.Errorf("failed to store MFA recovery codes: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("store MFA recovery codes failed: %s", resp.Error.Error())
	}
	return nil
}

func (rs *RemoteStorage) ConsumeMFARecoveryCode(_ context.Context, _ uint, _ string, _ time.Time) (bool, error) {
	return false, remoteUnsupported("ConsumeMFARecoveryCode")
}

// CountUnusedMFARecoveryCodes reports how many of a user's recovery codes
// remain unused via GET /api/v1/system/mfa/recovery-codes/count?user_id=X.
func (rs *RemoteStorage) CountUnusedMFARecoveryCodes(ctx context.Context, userID uint) (int, error) {
	q := url.Values{}
	q.Set("user_id", strconv.FormatUint(uint64(userID), 10))
	path := "/api/v1/system/mfa/recovery-codes/count?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("failed to count MFA recovery codes: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("count MFA recovery codes failed: %s", resp.Error.Error())
	}
	var result struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Count, nil
}

// DeleteMFARecoveryCodes removes ALL of a user's recovery codes via DELETE
// /api/v1/system/mfa/recovery-codes/{userId} — the regenerate flow's "clear old
// codes" half.
func (rs *RemoteStorage) DeleteMFARecoveryCodes(ctx context.Context, userID uint) error {
	path := fmt.Sprintf("/api/v1/system/mfa/recovery-codes/%d", userID)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete MFA recovery codes: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete MFA recovery codes failed: %s", resp.Error.Error())
	}
	return nil
}

func (rs *RemoteStorage) CreateMFAChallenge(_ context.Context, _ *models.MFAChallenge) error {
	return remoteUnsupported("CreateMFAChallenge")
}

// mfaChallengeWire mirrors models.MFAChallenge's fields exactly (snake_case).
// models.MFAChallenge tags TokenHash json:"-" to keep it out of USER-facing
// responses — irrelevant here, since this is an internal system-to-system wire
// format gated on users.write, matching webAuthnSessionWire's identical
// TokenHash precedent (remote_webauthn.go).
type mfaChallengeWire struct {
	ID        uint       `json:"id"`
	UserID    uint       `json:"user_id"`
	TokenHash string     `json:"token_hash"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func (w mfaChallengeWire) toModel() *models.MFAChallenge {
	return &models.MFAChallenge{
		ID:        w.ID,
		UserID:    w.UserID,
		TokenHash: w.TokenHash,
		ExpiresAt: w.ExpiresAt,
		UsedAt:    w.UsedAt,
		CreatedAt: w.CreatedAt,
	}
}

func decodeMFAChallengeResponse(data []byte) (*models.MFAChallenge, error) {
	var wire mfaChallengeWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// mfaChallengeLookupWire is the wire body shared by GetActiveMFAChallenge and
// ConsumeMFAChallenge below. It no longer carries `now` on the wire
// (G-wave6): the upstream server computes the expiry-comparison time itself
// from its own clock rather than trusting a value a caller could manipulate
// to keep an expired challenge usable or force a live one to look expired —
// see server/http/handlers/users_crud.go's mfaChallengeLookupBody doc
// comment. The `now` parameter below is kept on RemoteStorage's methods only
// for interface parity with LocalStorage (internal/core/storage.Storage);
// it is intentionally not sent.
type mfaChallengeLookupWire struct {
	TokenHash string `json:"token_hash"`
}

// ConsumeMFAChallenge atomically marks a valid (unused, unexpired) challenge used
// and returns it, via POST /api/v1/users/mfa-challenge/consume (#522) — the
// single-use gate FinishWebAuthnLogin spends before verifying the assertion. The
// atomicity guarantee is unchanged from LocalStorage's own implementation (an
// UPDATE ... WHERE used_at IS NULL AND expires_at > ? inside one DB transaction,
// local_mfa.go): the proxy handler calls storage.Storage.ConsumeMFAChallenge
// directly against the upstream's real storage in this single request, so the
// single-use invariant holds across this HTTP hop too — mirroring
// ConsumeWebAuthnSession's (#517) and MarkSetupTokenConsumed's (#510) identical
// one-round-trip-atomic-consume precedent, not a separate GET-then-mark-used
// pair that would reopen the exact concurrent-consume race those were built to
// close. This is an ordinary storage passthrough, NOT part of the
// RemoteMFAVerifier proxy above — see the package doc for why that split is
// correct here (the challenge row carries no secret of its own).
// now is accepted only for interface parity with LocalStorage — the
// upstream server ignores any caller-supplied "current time" and always
// uses its own clock (see mfaChallengeLookupWire's doc comment).
func (rs *RemoteStorage) ConsumeMFAChallenge(ctx context.Context, tokenHash string, _ time.Time) (*models.MFAChallenge, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/users/mfa-challenge/consume", mfaChallengeLookupWire{
		TokenHash: tokenHash,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid or expired challenge")
	}
	if !resp.Success {
		return nil, fmt.Errorf("invalid or expired challenge")
	}
	return decodeMFAChallengeResponse(resp.Data)
}

// GetActiveMFAChallenge resolves the (still-unconsumed) challenge
// BeginWebAuthnLogin needs to identify which user's passkeys to begin the
// assertion ceremony against, via POST /api/v1/users/mfa-challenge/active
// (#522). A read, not a consume: WebAuthn's two-step login (Begin then Finish)
// must look up the user WITHOUT spending the challenge's single use yet —
// ConsumeMFAChallenge above (called from FinishWebAuthnLogin) is what actually
// spends it, matching local_mfa.go's own GetActiveMFAChallenge/
// ConsumeMFAChallenge split exactly.
// now is accepted only for interface parity with LocalStorage — the
// upstream server ignores any caller-supplied "current time" and always
// uses its own clock (see mfaChallengeLookupWire's doc comment).
func (rs *RemoteStorage) GetActiveMFAChallenge(ctx context.Context, tokenHash string, _ time.Time) (*models.MFAChallenge, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/users/mfa-challenge/active", mfaChallengeLookupWire{
		TokenHash: tokenHash,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid or expired challenge")
	}
	if !resp.Success {
		return nil, fmt.Errorf("invalid or expired challenge")
	}
	return decodeMFAChallengeResponse(resp.Data)
}

// issueMFAChallengeWireResponse carries only the opaque challenge token: the
// upstream server minted and persisted the actual MFAChallenge row itself (it
// never crosses the wire), matching the "the caller never sees storage
// internals" boundary the rest of this proxy mechanism follows.
type issueMFAChallengeWireResponse struct {
	Challenge string `json:"challenge"`
}

// IssueMFAChallenge implements core.RemoteMFAVerifier: it asks the upstream
// server to mint the short-lived, single-use MFA challenge for userID (the SAME
// shape core.CreateMFAChallenge always minted, just persisted upstream via POST
// /api/v1/users/{id}/mfa-challenge instead of locally), gated by the same
// users.write permission CreateUser/UnlockUser/verify-credentials already
// require of the RemoteStorage service credential (#506/#509) — see the
// RemoteMFAVerifier doc in internal/core/mfa.go for why this is not a new,
// weaker trust boundary: the challenge alone grants nothing without the
// correct TOTP/recovery code that follows.
func (rs *RemoteStorage) IssueMFAChallenge(ctx context.Context, userID uint) (string, error) {
	resp, err := rs.client.Post(ctx, fmt.Sprintf("/api/v1/users/%d/mfa-challenge", userID), nil)
	if err != nil {
		return "", fmt.Errorf("failed to start MFA challenge")
	}
	if !resp.Success {
		return "", fmt.Errorf("failed to start MFA challenge")
	}
	var wire issueMFAChallengeWireResponse
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return "", fmt.Errorf("failed to start MFA challenge")
	}
	return wire.Challenge, nil
}

// verifyMFAWireRequest carries the plaintext TOTP/recovery code deliberately
// (see the package doc above and #506's precedent) — the upstream server needs
// it to run its own TOTP validation / recovery-code compare against the real,
// decrypted secret; there is no other way this check could ever work under
// storage.type: remote.
type verifyMFAWireRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

// verifyMFAWireResponse carries what core.VerifyMFALogin needs after a
// successful verdict: enough identity to mint/describe the session, whether a
// recovery code was used (for the audit event), and the two password-age fields
// that enforcePasswordExpiryGate (ADR-025) reads. PasswordChangedAt and
// CreatedAt are intentionally included: without them toModel() returns a sparse
// User where both fields are zero/nil, causing PasswordExpired() to always
// return false and silently bypassing the password-expiry hard gate on
// storage.type: remote spoke deployments. No TOTP secret, no recovery-code
// hashes, no lockout counters — those are meaningless here: the upstream already
// applied/cleared them before ever returning success.
type verifyMFAWireResponse struct {
	ID                uint       `json:"id"`
	Username          string     `json:"username"`
	UsedRecovery      bool       `json:"used_recovery"`
	PasswordChangedAt *time.Time `json:"password_changed_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

func (w verifyMFAWireResponse) toModel() *models.User {
	return &models.User{
		ID:                w.ID,
		Username:          w.Username,
		PasswordChangedAt: w.PasswordChangedAt,
		CreatedAt:         w.CreatedAt,
	}
}

// VerifyMFALoginCredentials implements core.RemoteMFAVerifier: it proxies the
// ENTIRE second-factor check — challenge consumption, TOTP/recovery-code
// verification, anti-replay (MarkTOTPStepUsed), and the per-account lockout/
// account-state gates — to the upstream server via POST
// /api/v1/users/verify-mfa, gated by the same users.write permission
// verify-credentials already requires (#506/#509).
//
// Every failure — an expired/consumed challenge, a wrong code, a tripped
// lockout, or a network/parse error — collapses to the SAME generic "invalid
// code" error here, mirroring VerifyLoginCredentials (remote_login_verify.go):
// the actual end-user-facing /auth/mfa/verify handler already collapses every
// failure reason to one generic 401 regardless of cause (server/http/handlers/
// mfa.go), so no caller-visible behavior is lost; this just keeps the internal
// proxy call from becoming a richer oracle than the direct path ever was.
func (rs *RemoteStorage) VerifyMFALoginCredentials(ctx context.Context, challenge, code string) (*models.User, bool, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/users/verify-mfa", verifyMFAWireRequest{
		Challenge: challenge,
		Code:      code,
	})
	if err != nil {
		return nil, false, fmt.Errorf("invalid code")
	}
	if !resp.Success {
		return nil, false, fmt.Errorf("invalid code")
	}
	var wire verifyMFAWireResponse
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, false, fmt.Errorf("invalid code")
	}
	return wire.toModel(), wire.UsedRecovery, nil
}

// UpsertMFAStepupToken and HasActiveMFAStepup are intentional stubs: the step-up
// token is created by VerifyMFALogin and checked by the classification gate on the
// same server node that holds the LocalStorage. RemoteStorage (a spoke CLI node) is
// never the node making these calls — the HTTP request for a restricted secret value
// goes straight to the upstream server, which checks its own local table.
func (rs *RemoteStorage) UpsertMFAStepupToken(_ context.Context, _ uint, _ time.Time) error {
	return remoteUnsupported("UpsertMFAStepupToken")
}

func (rs *RemoteStorage) HasActiveMFAStepup(_ context.Context, _ uint) (bool, error) {
	return false, remoteUnsupported("HasActiveMFAStepup")
}
