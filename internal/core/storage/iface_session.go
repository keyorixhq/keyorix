package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SessionStore is the Storage slice for login rate limiting, SSO login state and sessions.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type SessionStore interface {
	// Login rate limiting (ADR-040) — cluster-wide brute-force protection. Replaces
	// the per-process in-memory limiter so the limit holds across HA replicas.
	RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error
	CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error)
	PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error)

	// ReserveLoginAttempt is RecordLoginAttempt's releasable counterpart: it writes
	// the same row but returns its id, so a caller that reserves BEFORE a slow
	// check runs (closing the concurrent-burst race RecordLoginAttempt's own
	// callers rely on — see core.ReserveLoginAttempt) can undo the write via
	// ReleaseLoginAttempt if that check turns out not to be a confirmed negative
	// result. Every auth budget write goes through it, releasable or not (core
	// budgetWriteKeyed, #2837): the per-key idempotence is what makes a failed
	// write safe to retry. RecordLoginAttempt is left to the relay
	// (core.RecordLoginAttemptRelay), which returns the error to its caller.
	//
	// key is a caller-generated reservation identifier, unique per reservation
	// (#2956 follow-up). The write is idempotent per key: reserving the same key
	// again writes nothing and returns the existing row's id. That is what lets a
	// caller whose write landed but reported an error retry with the same key and
	// get the reservation back instead of losing it or counting it twice.
	ReserveLoginAttempt(ctx context.Context, ip string, at time.Time, key string) (id uint, err error)
	// ReleaseLoginAttempt deletes the LoginAttempt row `id`, undoing a prior
	// ReserveLoginAttempt. A no-op, not an error, if the row is already gone
	// (e.g. a maintenance prune raced it).
	ReleaseLoginAttempt(ctx context.Context, id uint) error

	// SSO login state (OIDC human SSO) — short-lived CSRF/nonce state.
	// ConsumeSSOLoginState is single-use: it returns the row and deletes it.
	CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error
	ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error)

	// Session Management
	CreateSession(ctx context.Context, session *models.Session) (*models.Session, error)
	// GetSession looks up a LIVE (not-yet-rotated) session by token. A token
	// belonging to a session RefreshSession has since rotated away must behave
	// exactly like a deleted one here (see RotatedAt on models.Session) — used on
	// every authenticated request and on Logout.
	GetSession(ctx context.Context, token string) (*models.Session, error)
	// GetSessionAny looks up a session by token regardless of rotation state.
	// Used only by RefreshSession's reuse-detection path (#211), which must tell an
	// already-rotated token (a reuse signal) apart from one that never existed.
	GetSessionAny(ctx context.Context, token string) (*models.Session, error)
	GetSessionByID(ctx context.Context, id uint) (*models.Session, error)
	// GetSessionAuthLiveness is GetUser(userID) plus GetSessionByID(sessionID)
	// in ONE statement (PERF-FIX-7, collapse C6): the HTTP auth middleware's
	// session cache-hit check reads the owning account's state and the session
	// row from one snapshot. Each half reports what its per-statement method
	// would have (see SessionAuthLiveness); a failure of the combined statement
	// is answered through those methods (ComposeSessionAuthLiveness).
	GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*SessionAuthLiveness, error)
	ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error)
	// EnforceSessionLimit deletes a user's oldest sessions beyond the `keep` most-recent
	// (by created_at), bounding concurrent sessions per user. No-op when under the cap.
	EnforceSessionLimit(ctx context.Context, userID uint, keep int) error
	DeleteSession(ctx context.Context, id uint) error
	// DeleteSessionsForUserExcept removes every session owned by userID except the
	// one with id exceptID. Used to drop other sessions on a password change.
	DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error
	// ListSessionTokenHashesForUser returns the stored session_token values (SHA-256
	// hashes — equal to the auth-cache key) for every session owned by or impersonating
	// userID, so a state change can evict them from the auth cache immediately.
	ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error)
	// RotateSession atomically supersedes the session at oldID with newSession inside
	// a single DB transaction (#211): the CAS guard (rotated_at IS NULL) makes
	// rotation race-free under concurrent refreshes of the same token — at most one
	// caller wins (won=true). The loser must treat the loss as a reuse signal exactly
	// like an out-of-band replay of an already-rotated token.
	RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (created *models.Session, won bool, err error)
	// ListSessionTokenHashesByFamily / DeleteSessionsByFamily revoke every session
	// descended from the same login (see FamilyID on models.Session) — used to kill
	// the whole lineage when a refresh-token reuse is detected (#211).
	ListSessionTokenHashesByFamily(ctx context.Context, familyID string) ([]string, error)
	DeleteSessionsByFamily(ctx context.Context, familyID string) error
	// TouchSession bumps last_seen_at only when it is older than the given staleness
	// window (no-op otherwise) so the auth hot path is not turned into a write per request.
	TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error
	CleanupExpiredSessions(ctx context.Context) error
}
