// remote_mfa.go — MFA persistence is server-side only; the remote client never
// manages MFA state directly (enrolment/verify go through the server's REST API).
//
// IssueMFAChallenge and VerifyMFALoginCredentials below implement
// core.RemoteMFAVerifier (#509): the upstream half of the storage.type: remote
// TOTP second-factor login proxy, mirroring remote_login_verify.go's password
// proxy (#506) exactly. The raw TOTP secret is stored reversibly encrypted
// specifically so it must never leave the server that can decrypt it —
// GetMFASecret below stays an unconditional stub for that reason — so the
// ENTIRE TOTP/recovery-code check, not just a wire-DTO passthrough of the
// storage primitives above, has to run upstream.
//
// GetActiveMFAChallenge and ConsumeMFAChallenge below are DIFFERENT from that
// pair: they are ordinary storage.Storage passthroughs (#522), not part of the
// RemoteMFAVerifier proxy. models.MFAChallenge is a SHARED pre-auth token: the
// SAME row backs both the TOTP path (proxied wholesale above, since it also
// needs the encrypted secret) and WebAuthn-as-second-factor login
// (internal/core/webauthn.go's BeginWebAuthnLogin/FinishWebAuthnLogin), which has
// no secret of its own to protect — a spoke server that resolves the
// challenge's user_id can run the entire passkey assertion ceremony locally
// against its own (already-proxied, #517) WebAuthn credential rows. Before this
// fix, BOTH were unconditional stubs, so WebAuthn login was 100% broken under
// storage.type: remote even though the TOTP path already worked.
//
// WebAuthn's OWN storage.Storage primitives (registered credentials, ceremony
// sessions) are handled separately: see remote_webauthn.go / #517.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) UpsertMFASecret(_ context.Context, _ *models.MFASecret) error {
	return remoteUnsupported("UpsertMFASecret")
}

func (rs *RemoteStorage) GetMFASecret(_ context.Context, _ uint) (*models.MFASecret, error) {
	return nil, remoteUnsupported("GetMFASecret")
}

func (rs *RemoteStorage) ActivateMFASecret(_ context.Context, _ uint) error {
	return remoteUnsupported("ActivateMFASecret")
}

func (rs *RemoteStorage) MarkTOTPStepUsed(_ context.Context, _ uint, _ int64) (bool, error) {
	return false, remoteUnsupported("MarkTOTPStepUsed")
}

func (rs *RemoteStorage) DeleteMFAForUser(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteMFAForUser")
}

func (rs *RemoteStorage) SetUserMFAEnabled(_ context.Context, _ uint, _ bool) error {
	return remoteUnsupported("SetUserMFAEnabled")
}

func (rs *RemoteStorage) CreateMFARecoveryCodes(_ context.Context, _ uint, _ []string) error {
	return remoteUnsupported("CreateMFARecoveryCodes")
}

func (rs *RemoteStorage) ConsumeMFARecoveryCode(_ context.Context, _ uint, _ string, _ time.Time) (bool, error) {
	return false, remoteUnsupported("ConsumeMFARecoveryCode")
}

func (rs *RemoteStorage) CountUnusedMFARecoveryCodes(_ context.Context, _ uint) (int, error) {
	return 0, remoteUnsupported("CountUnusedMFARecoveryCodes")
}

func (rs *RemoteStorage) DeleteMFARecoveryCodes(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteMFARecoveryCodes")
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
// ConsumeMFAChallenge below — both take the identical (tokenHash, now) pair
// internal/core/webauthn.go already passes to storage.Storage's local
// implementation (local_mfa.go).
type mfaChallengeLookupWire struct {
	TokenHash string    `json:"token_hash"`
	Now       time.Time `json:"now"`
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
func (rs *RemoteStorage) ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/users/mfa-challenge/consume", mfaChallengeLookupWire{
		TokenHash: tokenHash,
		Now:       now,
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
func (rs *RemoteStorage) GetActiveMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/users/mfa-challenge/active", mfaChallengeLookupWire{
		TokenHash: tokenHash,
		Now:       now,
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

// verifyMFAWireResponse is deliberately narrow — it carries exactly what
// core.VerifyMFALogin needs after a successful verdict (enough identity to
// mint/describe the session, plus whether a recovery code was used for the
// matching audit event) and nothing else: no TOTP secret, no recovery-code
// hashes, no lockout-accounting counters (meaningless here — the upstream
// already applied/cleared them before ever returning success).
type verifyMFAWireResponse struct {
	ID           uint   `json:"id"`
	Username     string `json:"username"`
	UsedRecovery bool   `json:"used_recovery"`
}

func (w verifyMFAWireResponse) toModel() *models.User {
	return &models.User{ID: w.ID, Username: w.Username}
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
