// data_retention.go — per-record-type retention purge of compliance records
// (ISO 27001 A.5.33 / GDPR storage-limitation / DORA record-keeping).
//
// The ADR-032 purge (purge.go) ages out soft-deleted users/projects/secrets; the
// audit trail is append-only and never purged (ADR-029). This file covers the
// compliance records that otherwise accumulate forever — anomaly alerts, closed
// recertification campaigns, the break-glass register, and resolved access
// requests — deleting each past its own configurable window. Active/open/pending
// records are excluded at the storage layer, and the scheduler skips entirely
// while a legal hold is active, so nothing under hold is destroyed.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RetentionPolicy is the resolved set of per-record-type retention windows, in
// days. A window of 0 disables retention for that type (records kept forever).
// It mirrors config.DataRetentionConfig but lives in core so the scheduler and the
// compliance posture can share it without core importing the config package. Set
// at startup via SetRetentionPolicy.
type RetentionPolicy struct {
	AnomalyAlertsDays          int
	ClosedAccessReviewsDays    int
	BreakGlassDays             int
	ResolvedAccessRequestsDays int
}

// Configured reports whether at least one retention window is active.
func (p RetentionPolicy) Configured() bool {
	return p.AnomalyAlertsDays > 0 || p.ClosedAccessReviewsDays > 0 ||
		p.BreakGlassDays > 0 || p.ResolvedAccessRequestsDays > 0
}

// RetentionResult reports how many records each per-type retention purge removed.
// AccessReviewItems and AccessRequestApprovals are dependent rows cascaded with
// their parent (closed campaigns / resolved requests).
type RetentionResult struct {
	AnomalyAlerts          int64 `json:"anomaly_alerts"`
	ClosedAccessReviews    int64 `json:"closed_access_reviews"`
	AccessReviewItems      int64 `json:"access_review_items"`
	BreakGlass             int64 `json:"break_glass"`
	ResolvedAccessRequests int64 `json:"resolved_access_requests"`
	AccessRequestApprovals int64 `json:"access_request_approvals"`
}

// Total is the combined count of records removed across every type.
func (r RetentionResult) Total() int64 {
	return r.AnomalyAlerts + r.ClosedAccessReviews + r.AccessReviewItems +
		r.BreakGlass + r.ResolvedAccessRequests + r.AccessRequestApprovals
}

// SetRetentionPolicy records the configured per-type retention windows so the
// compliance posture can report them. The scheduler (main.go) drives the actual
// purge from config; this setter exists for the read-only posture view. The
// server calls it once at startup from keyorix.yaml (#160): an operator with
// filesystem+restart access who shortens a retention window otherwise leaves no
// audit trail of the CHANGE itself, only of the resulting purge counts — this
// records the configured windows every time they're applied, mirroring
// AuditLicenseState's startup-audit pattern.
func (c *KeyorixCore) SetRetentionPolicy(ctx context.Context, p RetentionPolicy) {
	c.retentionPolicy = p
	ok := true
	c.emitAudit(ctx, &models.AuditEvent{
		EventType: "data_retention.policy_configured",
		Description: fmt.Sprintf(
			"Data retention policy applied: anomaly_alerts=%dd closed_access_reviews=%dd break_glass=%dd resolved_access_requests=%dd",
			p.AnomalyAlertsDays, p.ClosedAccessReviewsDays, p.BreakGlassDays, p.ResolvedAccessRequestsDays,
		),
		Success:   &ok,
		ActorType: ActorTypeSystem,
		EventTime: time.Now(),
	})
}

// RetentionPolicy returns the configured retention windows (zero value if unset).
func (c *KeyorixCore) RetentionPolicy() RetentionPolicy {
	return c.retentionPolicy
}

// PurgeExpiredComplianceRecords hard-deletes compliance records older than each
// type's retention window, computed from `now`. A type with a zero-day window is
// skipped (kept forever). Per-type errors are collected but do not abort the other
// types. When anything was removed it emits one system-actored
// `data.retention_purged` audit event with the per-type counts.
//
// CALLERS MUST gate this on legal-hold status (the scheduler does): an active hold
// must preserve all records, so this is not invoked while a hold is in effect.
func (c *KeyorixCore) PurgeExpiredComplianceRecords(ctx context.Context, now time.Time, policy RetentionPolicy) (*RetentionResult, error) {
	// Authoritative legal-hold re-check inside the locked purge (see PurgeExpiredSoftDeletes):
	// closes the TOCTOU where a hold placed after the scheduler's pre-lock check would not
	// stop the in-flight deletion of compliance records. Fails SAFE.
	if err := c.legalHoldGuard(ctx); err != nil {
		return &RetentionResult{}, err
	}
	res := &RetentionResult{}
	var firstErr error
	rec := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	cutoff := func(days int) time.Time { return now.AddDate(0, 0, -days) }

	if policy.AnomalyAlertsDays > 0 {
		n, err := c.storage.DeleteAnomalyAlertsBefore(ctx, cutoff(policy.AnomalyAlertsDays))
		rec(err)
		res.AnomalyAlerts = n
	}
	if policy.ClosedAccessReviewsDays > 0 {
		camp, items, err := c.storage.DeleteClosedAccessReviewsBefore(ctx, cutoff(policy.ClosedAccessReviewsDays))
		rec(err)
		res.ClosedAccessReviews = camp
		res.AccessReviewItems = items
	}
	if policy.BreakGlassDays > 0 {
		n, err := c.storage.DeleteExpiredBreakGlassBefore(ctx, cutoff(policy.BreakGlassDays))
		rec(err)
		res.BreakGlass = n
	}
	if policy.ResolvedAccessRequestsDays > 0 {
		reqs, appr, err := c.storage.DeleteResolvedAccessRequestsBefore(ctx, cutoff(policy.ResolvedAccessRequestsDays))
		rec(err)
		res.ResolvedAccessRequests = reqs
		res.AccessRequestApprovals = appr
	}

	if res.Total() > 0 {
		sysCtx := WithActorType(ctx, ActorTypeSystem)
		c.writeAuditEvent(sysCtx, "data.retention_purged", nil, nil,
			fmt.Sprintf("data-retention purge removed %d compliance records (anomaly_alerts=%d, closed_campaigns=%d, review_items=%d, break_glass=%d, access_requests=%d, approvals=%d)",
				res.Total(), res.AnomalyAlerts, res.ClosedAccessReviews, res.AccessReviewItems,
				res.BreakGlass, res.ResolvedAccessRequests, res.AccessRequestApprovals))
	}
	return res, firstErr
}
