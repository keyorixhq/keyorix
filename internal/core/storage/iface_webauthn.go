package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// WebAuthnStore is the Storage slice for WebAuthn credentials and ceremony sessions.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type WebAuthnStore interface {
	// WebAuthn / passkeys (ADR-036).
	CreateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error
	ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error)
	// GetWebAuthnCredentialByCredID looks up a credential by its (unique) credential
	// ID, scoped to the claimed owner: the query itself requires user_id = userID, so
	// correctness does not depend on every caller re-checking ownership after the
	// fetch (#307).
	GetWebAuthnCredentialByCredID(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error)
	// LockWebAuthnCredentialForUpdate re-reads a WebAuthn credential by (credential_id,
	// user_id), taking a row-level write lock on backends that support one
	// (Postgres: SELECT … FOR UPDATE). This is now an ORDINARY (non-atomic) read
	// primitive: it and UpdateWebAuthnCredential remain for callers that read/write a
	// credential outside the signature-counter race (e.g. a plain lookup, or
	// rejectIfCloned's best-effort "mark disabled" write, whose worst outcome under a
	// lost race is a harmless redundant write, not a security regression). The
	// counter-advance path that USED to compose these two into a single
	// WithTransaction call (closing the cloned-authenticator race, #306) now goes
	// through AdvanceWebAuthnCredentialCounter below instead, which performs the
	// lock+compare+write as ONE atomic storage-layer call — required because the
	// now-deleted RemoteStorage's WithTransaction was a no-op passthrough:
	// composing LockWebAuthnCredentialForUpdate + UpdateWebAuthnCredential as two
	// separate remote calls would have reopened the exact TOCTOU race the
	// transaction was built to prevent.
	LockWebAuthnCredentialForUpdate(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error)
	// DisableWebAuthnCredential sets ONLY `disabled = true` on an EXISTING
	// credential row, returning matched=false when the row is gone.
	// SetWebAuthnCredentialCounterState persists ONLY the signature-counter blob
	// and last_used_at.
	//
	// Together they REPLACE the former UpdateWebAuthnCredential, a bare GORM Save
	// (#2700). WebAuthnCredential is HARD-deleted (no DeletedAt), so Save's
	// 0-rows fallback — `INSERT ... ON CONFLICT (id) DO UPDATE` — re-inserted a
	// passkey the user had just deleted. It came back with Disabled=true, so it
	// fails closed for authentication; what it corrupts is the credential count
	// and the webauthn_enabled bookkeeping derived from it. Low severity, and
	// deliberately described as such.
	DisableWebAuthnCredential(ctx context.Context, id uint) (matched bool, err error)
	SetWebAuthnCredentialCounterState(ctx context.Context, id uint, blob []byte, lastUsedAt time.Time) (matched bool, err error)
	// AdvanceWebAuthnCredentialCounter conditionally persists an advanced signature
	// counter (newBlob/newSignCount) and lastUsedAt for the credential identified by
	// (credentialID, userID), IFF newSignCount is not stale relative to whatever
	// counter is CURRENTLY persisted — the single atomic primitive
	// persistUpdatedCredential (internal/core/webauthn.go) is built on to close the
	// cloned-authenticator race (#306/#517): two concurrent logins asserting the same
	// credential must never let the loser's stale, lower counter clobber the
	// winner's already-persisted higher one. "Not stale" mirrors go-webauthn's own
	// Authenticator.UpdateCounter gate exactly: a (0, 0) comparison (many platform
	// authenticators never implement a counter and always report 0) is never
	// stale — only reject when at least one side is nonzero and newSignCount fails to
	// strictly exceed the row's current stored count.
	//
	// LocalStorage implements this as a single row-locked transaction — the exact
	// Lock+compare+Update sequence persistUpdatedCredential used to run inline,
	// moved down into this one storage-layer call. (The now-deleted RemoteStorage
	// implemented it as ONE HTTP call whose server-side handler performed the
	// identical locked compare-and-swap against its own storage, since its
	// WithTransaction could not provide client-side atomicity at all.)
	//
	// Returns advanced=false, err=nil (not an error) when the write was skipped as
	// stale — a benign, expected outcome of losing a race, not a failure — mirroring
	// persistUpdatedCredential's pre-existing best-effort semantics (a write failure
	// here must never fail an otherwise-valid login). err is reserved for a genuine
	// storage-layer failure (e.g. the credential row doesn't exist).
	AdvanceWebAuthnCredentialCounter(ctx context.Context, credentialID []byte, userID uint, newBlob []byte, newSignCount uint32, lastUsedAt time.Time) (advanced bool, err error)
	DeleteWebAuthnCredential(ctx context.Context, userID, id uint) error
	CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error)
	SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error
	CreateWebAuthnSession(ctx context.Context, s *models.WebAuthnSession) error
	// ConsumeWebAuthnSession atomically finds an unused, unexpired ceremony session
	// by token hash, marks it used, and returns it (or an error if none).
	ConsumeWebAuthnSession(ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error)
}
