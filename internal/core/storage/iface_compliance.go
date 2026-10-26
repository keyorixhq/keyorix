package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ComplianceStore is the Storage slice for legal holds, risk exceptions and break-glass activations.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type ComplianceStore interface {
	// Legal hold (ISO 27001 A.5.34 / eDiscovery) — a deployment-wide hold that
	// blocks the purge jobs from hard-deleting records while active.
	CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error)
	GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error)
	UpdateLegalHold(ctx context.Context, h *models.LegalHold) error

	// Risk exceptions (ISO 27001 A.5.8 risk treatment) — governed, time-bound
	// acceptances of a known control gap. CreateRiskException records one;
	// ListRiskExceptions returns all (activeOnly excludes revoked rows; expiry is
	// computed in core); GetRiskException/RevokeRiskExceptionIfNotRevoked support
	// revoke.
	CreateRiskException(ctx context.Context, e *models.RiskException) (*models.RiskException, error)
	ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error)
	GetRiskException(ctx context.Context, id uint) (*models.RiskException, error)
	// RevokeRiskExceptionIfNotRevoked persists e's full row (Revoked/RevokedBy/
	// RevokedAt already set by the caller) via a single conditional UPDATE —
	// "WHERE id = ? AND revoked = false" — succeeding only if the row's CURRENT
	// persisted revoked flag is still false, mirroring TransitionMachineIdentityState's
	// `WHERE id = ? AND state = ?` pattern (#388) and UpdateProjectInvitation's
	// `WHERE id = ? AND state = 'pending'` pattern (#412) for this same TOCTOU class.
	// The bool reports whether the row matched and was updated; false means the
	// exception was already revoked by a prior or racing call (e.g. a concurrent
	// RevokeRiskException or ApproveRiskException) and this write was rejected, not
	// silently applied. core.RevokeRiskException's own precondition check
	// (e.Revoked) only protects against the case where the initial read already
	// showed revoked=true — it does nothing for a revoke that happens in the
	// window between that read and this write, which is exactly the gap this
	// conditional UPDATE closes.
	//
	// This exists — rather than a plain full-row overwrite — for the same reason
	// TransitionMachineIdentityState does: the now-deleted RemoteStorage's
	// WithTransaction was a no-op passthrough, so a caller-driven
	// read-then-conditional-write sequence run against it got none of the
	// atomicity a real DB transaction + row lock gives LocalStorage. Routing the
	// write through this one conditional round trip — a single LocalStorage
	// conditional SQL UPDATE — restores the guarantee.
	RevokeRiskExceptionIfNotRevoked(ctx context.Context, e *models.RiskException) (bool, error)
	// ApproveRiskExceptionIfPending persists e's full row (Approved/ApprovedBy/
	// ApprovedAt already set by the caller) via a single conditional UPDATE —
	// "WHERE id = ? AND revoked = false AND approved = false" — succeeding only if
	// the row is CURRENTLY still un-revoked AND un-approved. See
	// RevokeRiskExceptionIfNotRevoked's doc for why this exists as a dedicated
	// conditional round trip rather than a plain full-row overwrite. The
	// bool reports whether the row matched and was updated; false means the
	// exception was concurrently revoked, or already approved, by a prior or
	// racing call and this write was rejected, not silently applied.
	ApproveRiskExceptionIfPending(ctx context.Context, e *models.RiskException) (bool, error)

	// Break-glass emergency-access activations (NIS2/DORA incident response).
	// GetBreakGlassActivation/ListBreakGlassActivations project State to
	// 'expired' for a TTL-lapsed 'active' row (watermark-clamped) as a pure
	// read-time computation -- never persisted from either (#1653 reopened: a
	// list/get read path persisting an access-control-adjacent state transition
	// was the actual defect, not merely a premise nobody had asserted).
	CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error)
	GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error)
	ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error)
	UpdateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) error
	// ReconcileExpiredBreakGlassActivation transitions userID's own TTL-lapsed
	// 'active' row in projectID to 'expired' (watermark-clamped), if one
	// exists. The one place a TTL-lapse transition is ever persisted -- called
	// only from ActivateBreakGlass, a mutating operation, immediately before it
	// attempts to create a new activation, so a genuinely-expired-but-never-
	// revisited prior row doesn't hold the one-active-slot-per-(project,user)
	// partial unique index forever.
	ReconcileExpiredBreakGlassActivation(ctx context.Context, projectID, userID uint) error
	// RevokeBreakGlassActivation atomically transitions activation id from
	// active-OR-expired to revoked, recording who revoked it and when, via a
	// single conditional UPDATE rather than a read-modify-write — so two
	// concurrent revokes of the same activation cannot both "win": only the
	// first transitions state, and the second gets ErrBreakGlassNotActive
	// rather than silently overwriting the first revoker's attribution.
	// Accepts 'expired' as well as 'active' so a caller is never refused a
	// revoke because of what a clock-derived State happens to read; only an
	// already-'revoked' row is excluded.
	RevokeBreakGlassActivation(ctx context.Context, id, revokedBy, revokedByMachineID uint, revokedAt time.Time) error
	// ReviewBreakGlassActivation (ADR-112 §3, break-glass review item 5)
	// atomically records a post-activation review -- reviewer, when, and an
	// optional note -- via a single conditional UPDATE guarded on
	// reviewed_at IS NULL, the same shape as RevokeBreakGlassActivation's
	// guard, so two concurrent review submissions for the same activation
	// cannot both "win": only the first is recorded, the second gets
	// ErrBreakGlassAlreadyReviewed. This storage-layer primitive itself does
	// not condition on active/expired/revoked state -- it records a review
	// against whatever row id names. #2461 round 2: that is NOT the same as
	// "a review is allowed at any state" -- core.ReviewBreakGlass, the only
	// production caller, refuses a still-active activation BEFORE reaching
	// here (ErrBreakGlassStillActive), so in practice this is only ever
	// called once the activation has concluded.
	ReviewBreakGlassActivation(ctx context.Context, id, reviewerID uint, note string, reviewedAt time.Time) error
	// ListUnreviewedBreakGlassActivationsBefore returns every activation
	// (across all projects) with reviewed_at still NULL and created_at at or
	// before cutoff, plus every unreviewed DEGRADED activation whatever its age
	// (its review is mandatory at once, BREAKGLASS-OWED-1) -- the posture
	// report's (item 4) source for "open break-glass activations without
	// review."
	ListUnreviewedBreakGlassActivationsBefore(ctx context.Context, cutoff time.Time) ([]*models.BreakGlassActivation, error)
	// SettleBreakGlassOwedAudit (BREAKGLASS-OWED-1) marks degraded activation id
	// settled at settledAt when no pending_audit_events row linked to it remains,
	// and reports whether this call settled it. Run in the backfill transaction
	// that claims and appends the activation's last owed row, so "settled" and the
	// row being in the chain commit together.
	SettleBreakGlassOwedAudit(ctx context.Context, id uint, settledAt time.Time) (settled bool, err error)
	// ListUnsettledBreakGlassActivations returns every degraded activation whose
	// owed audit rows are not all in the hash chain yet, oldest first.
	ListUnsettledBreakGlassActivations(ctx context.Context) ([]*models.BreakGlassActivation, error)
}
