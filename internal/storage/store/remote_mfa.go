// remote_mfa.go — MFA persistence is server-side only; the remote client never
// manages MFA state directly (enrolment/verify go through the server's REST API).
//
// The two exceptions are IssueMFAChallenge and VerifyMFALoginCredentials below,
// which implement core.RemoteMFAVerifier (#509): the upstream half of the
// storage.type: remote second-factor login proxy, mirroring
// remote_login_verify.go's password proxy (#506) exactly. The raw TOTP secret
// is stored reversibly encrypted specifically so it must never leave the
// server that can decrypt it — GetMFASecret below stays an unconditional stub
// for that reason — so the ENTIRE TOTP/recovery-code check, not just a wire-DTO
// passthrough of the storage primitives above, has to run upstream.
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

func (rs *RemoteStorage) ConsumeMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, remoteUnsupported("ConsumeMFAChallenge")
}

func (rs *RemoteStorage) GetActiveMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, remoteUnsupported("GetActiveMFAChallenge")
}

// WebAuthn persistence is server-side only (ADR-036); the remote client manages
// passkeys through the server's REST API, not the storage interface directly.
func (rs *RemoteStorage) CreateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return remoteUnsupported("CreateWebAuthnCredential")
}
func (rs *RemoteStorage) ListWebAuthnCredentials(_ context.Context, _ uint) ([]*models.WebAuthnCredential, error) {
	return nil, remoteUnsupported("ListWebAuthnCredentials")
}
func (rs *RemoteStorage) GetWebAuthnCredentialByCredID(_ context.Context, _ []byte, _ uint) (*models.WebAuthnCredential, error) {
	return nil, remoteUnsupported("GetWebAuthnCredentialByCredID")
}
func (rs *RemoteStorage) LockWebAuthnCredentialForUpdate(_ context.Context, _ []byte, _ uint) (*models.WebAuthnCredential, error) {
	return nil, remoteUnsupported("LockWebAuthnCredentialForUpdate")
}
func (rs *RemoteStorage) UpdateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return remoteUnsupported("UpdateWebAuthnCredential")
}
func (rs *RemoteStorage) DeleteWebAuthnCredential(_ context.Context, _, _ uint) error {
	return remoteUnsupported("DeleteWebAuthnCredential")
}
func (rs *RemoteStorage) CountWebAuthnCredentials(_ context.Context, _ uint) (int64, error) {
	return 0, remoteUnsupported("CountWebAuthnCredentials")
}
func (rs *RemoteStorage) SetUserWebAuthnEnabled(_ context.Context, _ uint, _ bool) error {
	return remoteUnsupported("SetUserWebAuthnEnabled")
}
func (rs *RemoteStorage) CreateWebAuthnSession(_ context.Context, _ *models.WebAuthnSession) error {
	return remoteUnsupported("CreateWebAuthnSession")
}
func (rs *RemoteStorage) ConsumeWebAuthnSession(_ context.Context, _ string, _ time.Time) (*models.WebAuthnSession, error) {
	return nil, remoteUnsupported("ConsumeWebAuthnSession")
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
