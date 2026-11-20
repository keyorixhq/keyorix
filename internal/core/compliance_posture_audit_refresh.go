// compliance_posture_audit_refresh.go — COMPLIANCE-TILE-NOV-1 item 2 (#4186
// follow-up): the audit-integrity tile used to show the scheduler's last tail
// check, which is written once per verification interval (daily by default), so
// the tile could say 13 chained events while `audit verify` walked 259.
//
// Why recompute on request and not refresh on a timer: a timer needs a new
// scheduler wired into server/main.go, its own lock and its own failure handling,
// and would walk the chain every few minutes on a deployment nobody is looking
// at. Recomputing when a request finds the value older than auditPostureRefreshAfter
// costs a walk only while somebody reads the posture, needs no wiring, and uses
// the very check `audit verify` runs, so the two agree to within the window.
package core

import (
	"context"
	"log"
	"time"
)

// auditPostureRefreshAfter is how old the cached chain check may be before a
// posture request recomputes it. Between auditPostureFreshWindow and this age the
// tile is served from the cache and marked Stale, with the newer-events count.
const auditPostureRefreshAfter = 5 * time.Minute

// auditPostureCache is the last chain check a posture request produced.
type auditPostureCache struct {
	report *AuditVerifyReport
	// attemptedAt is when the check was last tried, successful or not: a failing
	// check is retried after auditPostureRefreshAfter, not on every page load.
	attemptedAt time.Time
	// refreshFailed means the last attempt failed and report is the persisted
	// scheduler state read in its place, not a walk.
	refreshFailed bool
}

// auditPostureReportPersistedTimeout bounds the persisted-state read that stands in
// for a failed walk. It runs detached from the request's cancellation so a walk
// that failed on the request's own deadline still gets the recorded verdict.
const auditPostureReportPersistedTimeout = 5 * time.Second

// auditPostureReport returns the chain verdict the posture shows and whether it
// is not a fresh walk because the refresh failed (the caller marks the tile
// stale). A refresh failure never serves an older walk: the verdict then comes
// from the persisted scheduler state, exactly what the posture showed before
// this cache existed, so a break or an overdue check the scheduler recorded
// since the last walk is shown (REVIEW-4539 MEDIUM-1). Without incremental
// verification configured every call is a full walk, as before.
func (c *KeyorixCore) auditPostureReport(ctx context.Context) (*AuditVerifyReport, bool, error) {
	if !c.auditIncrementalEnabled() {
		r, err := c.AuditVerificationStatus(ctx)
		return r, false, err
	}

	// One refresh at a time: requests that arrive during a walk wait for it and
	// then read its result instead of starting their own.
	c.auditPostureMu.Lock()
	defer c.auditPostureMu.Unlock()
	// A caller that left while it waited gets nothing: do not walk for it.
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	now := c.now()
	if prev := c.auditPosture; prev != nil && c.auditPostureCacheUsable(ctx, prev, now) {
		return copyAuditReport(prev.report), prev.refreshFailed, nil
	}

	walk := c.auditPostureWalk
	if walk == nil {
		walk = c.VerifyAuditChainIncremental
	}
	r, err := walk(ctx)
	if err == nil {
		// The walk happened now; the report's own LastCheckedAt is the
		// scheduler's last tick, which is what made the tile look old.
		r.LastCheckedAt = &now
		c.auditPosture = &auditPostureCache{report: r, attemptedAt: now}
		return copyAuditReport(r), false, nil
	}

	log.Printf("compliance posture: audit chain refresh failed, showing the persisted verification state: %v", err)
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditPostureReportPersistedTimeout)
	defer cancel()
	kept, perr := c.AuditVerificationStatus(pctx)
	if perr != nil {
		return nil, false, perr
	}
	if ctx.Err() == nil {
		// A request that went away says nothing about the check: do not let it
		// hold the retry back for the whole window.
		c.auditPosture = &auditPostureCache{report: kept, attemptedAt: now, refreshFailed: true}
	}
	return copyAuditReport(kept), true, nil
}

// auditPostureCacheUsable reports whether prev may be served instead of a walk:
// it was attempted at most auditPostureRefreshAfter ago (a clock that stepped
// backwards makes the age negative, which does not count as fresh), and the
// persisted state has not recorded a break the cached value does not show. The
// state read is one row; when it fails the age alone decides.
func (c *KeyorixCore) auditPostureCacheUsable(ctx context.Context, prev *auditPostureCache, now time.Time) bool {
	age := now.Sub(prev.attemptedAt)
	if age < 0 || age > auditPostureRefreshAfter {
		return false
	}
	if prev.report.Status == AuditVerifyStatusBroken {
		return true
	}
	st, err := c.AuditVerificationStatus(ctx)
	return err != nil || st.Status != AuditVerifyStatusBroken
}

// copyAuditReport returns a shallow copy so callers cannot change the cached
// report's own fields. Its pointer fields (Coverage, RollingCycle, LastFull*)
// still point into the cached value: every consumer only reads them, and one
// that writes through them must deep-copy first.
func copyAuditReport(r *AuditVerifyReport) *AuditVerifyReport {
	cp := *r
	return &cp
}
