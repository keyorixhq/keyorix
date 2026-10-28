package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MFAStore is the Storage slice for TOTP secrets, recovery codes, MFA challenges and step-up.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type MFAStore interface {
	// Administrator MFA resets (RECOVERY-MFA-RESET-1), iface_mfa_reset.go.
	MFAResetStore
	// MFA / TOTP (per-user two-factor authentication).
	// UpsertMFASecret stores s as the user's pending TOTP secret: it inserts the
	// row, or replaces an existing row that is NOT activated. It never replaces an
	// activated secret (#2692): the replace is conditional in the same statement,
	// and an activated row yields ErrMFASecretActivated with nothing written. A
	// caller's earlier read of MFAEnabled=false is therefore not what protects an
	// enabled account; a concurrent ActivateMFA that commits first wins.
	UpsertMFASecret(ctx context.Context, s *models.MFASecret) error
	GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error)
	// ActivateMFASecret marks userID's TOTP secret activated only if its stored
	// ciphertext still equals secretEnc, the row ActivateMFA validated the code
	// against (#2655). matched=false means a concurrent BeginMFAEnrollment
	// replaced the secret in between; nothing was written and the caller must
	// fail closed rather than activate a secret no code was checked against.
	ActivateMFASecret(ctx context.Context, userID uint, secretEnc []byte) (matched bool, err error)
	// MarkTOTPStepUsed atomically records that the given TOTP time-step was accepted for
	// userID, returning true only if it was newly consumed (step strictly greater than
	// the stored last-used step). A false return means the code is a replay.
	MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error)
	// ReleaseTOTPStepIfUnchanged reverts a step MarkTOTPStepUsed just marked as
	// used back to step-1 (re-permitting exactly that step), but ONLY if the
	// stored last-used step still equals step unchanged since the mark — a CAS
	// guard so this never regresses the anti-replay counter past a step some
	// OTHER, later-arriving request has since legitimately advanced it to.
	// Returns false (no error) when the CAS didn't match (nothing released).
	// Exists for #2567: a caller that marked a step used and then failed to
	// complete the side effect that depended on it (minting a session) can
	// give the user back their one attempt at that same code, instead of
	// forcing a wait for the next 30s time-step over a storage hiccup that had
	// nothing to do with the code itself.
	ReleaseTOTPStepIfUnchanged(ctx context.Context, userID uint, step int64) (bool, error)
	DeleteMFAForUser(ctx context.Context, userID uint) error // clears secret + recovery codes
	SetUserMFAEnabled(ctx context.Context, userID uint, enabled bool) error
	CreateMFARecoveryCodes(ctx context.Context, userID uint, codeHashes []string) error
	// ConsumeMFARecoveryCode marks a matching unused code used and reports whether one was consumed.
	ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error)
	// CountUnusedMFARecoveryCodes returns how many of the user's recovery codes remain unused.
	CountUnusedMFARecoveryCodes(ctx context.Context, userID uint) (int, error)
	// DeleteMFARecoveryCodes removes all of the user's recovery codes (the regenerate flow replaces them).
	DeleteMFARecoveryCodes(ctx context.Context, userID uint) error

	CreateMFAChallenge(ctx context.Context, c *models.MFAChallenge) error
	// ConsumeMFAChallenge atomically finds an unused, unexpired challenge by token
	// hash, marks it used, and returns it (or an error if none).
	ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)
	// GetActiveMFAChallenge finds an unused, unexpired challenge by token hash
	// WITHOUT consuming it (used to resolve the user at WebAuthn login-begin; the
	// challenge is consumed later, atomically, at login-finish).
	GetActiveMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)

	// UpsertMFAStepupToken records (or refreshes) the MFA step-up window for
	// userID. expiresAt is set by the caller (core) from the configured window. One
	// row per user; the previous row is replaced on re-verification so re-login
	// extends the window cleanly. (The now-deleted RemoteStorage implemented this
	// as an intentional no-op stub — the step-up token was always created and
	// checked server-side.)
	UpsertMFAStepupToken(ctx context.Context, userID uint, expiresAt time.Time) error
	// HasActiveMFAStepup reports whether userID has a non-expired MFA step-up
	// record, confirming a recent second-factor verification.
	HasActiveMFAStepup(ctx context.Context, userID uint) (bool, error)

	// CreateMFAStepUpGrant persists a new MFA step-up grant for userID. The
	// grant's Purpose field must be set by the caller (core) — it is what
	// GetActiveMFAStepUpGrant matches on, so a grant minted for one purpose can
	// never be misread as authorizing a different one.
	CreateMFAStepUpGrant(ctx context.Context, grant *models.MFAStepUpGrant) error
	// GetActiveMFAStepUpGrant returns the most recent non-expired MFA step-up
	// grant for userID AND purpose as of now, or (nil, nil) when none exists.
	// purpose is a required exact match, not a filter of convenience: a grant
	// minted for models.MFAStepUpPurposeRestrictedSecretRead must never satisfy
	// a query for models.MFAStepUpPurposeReauth or vice versa.
	GetActiveMFAStepUpGrant(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose, now time.Time) (*models.MFAStepUpGrant, error)
	// ConsumeMFAStepUpGrant atomically marks every live (unconsumed, unexpired)
	// grant for (userID, purpose) as consumed and reports whether any were
	// found — the single-use variant of GetActiveMFAStepUpGrant, mirroring
	// ConsumeMFARecoveryCode/ConsumeWebAuthnSession's conditional-UPDATE shape
	// (no read-then-write race: two near-simultaneous callers racing the same
	// live grant can never both observe consumed=true). requireReauth is the
	// sole intended caller, and only for models.MFAStepUpPurposeReauth — that
	// purpose must be single-use-per-action (one re-auth proof must not
	// authorize disabling MFA, deleting a WebAuthn credential, regenerating
	// recovery codes, AND changing the account email all from the same proof).
	// models.MFAStepUpPurposeRestrictedSecretRead grants are deliberately never
	// passed here; they stay multi-use for the window's duration via the
	// non-consuming GetActiveMFAStepUpGrant/HasActiveMFAStepUp.
	ConsumeMFAStepUpGrant(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose, now time.Time) (bool, error)
	// DeleteMFAStepUpGrantsFor removes all step-up grants for userID (used on
	// session revocation or security-incident response).
	DeleteMFAStepUpGrantsFor(ctx context.Context, userID uint) error
	// PruneMFAStepUpGrants removes MFAStepUpGrant rows whose ExpiresAt predates
	// `before`, returning how many were removed (store-mfa-002: each successful
	// VerifyMFAStepUp creates a new grant row, kept briefly past its own expiry
	// for audit purposes — see internal/storage/store/local_mfa_stepup_grant.go
	// — but with no bound this grows without limit). The sole intended caller is
	// internal/core.KeyorixCore.PruneMFAStepUpGrants, which computes and clamps
	// the cutoff; callers should not invoke this directly with an
	// externally-influenced `before`.
	PruneMFAStepUpGrants(ctx context.Context, before time.Time) (int64, error)
}
