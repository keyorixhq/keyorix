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
	// refreshFailed means the last attempt failed and report is an older value.
	refreshFailed bool
}

// auditPostureReport returns the chain verdict the posture shows and whether it
// is an older value kept because the refresh failed (the caller marks the tile
// stale). A refresh failure never fails the page: the previous value is kept, or,
// when there is none, the persisted scheduler state the posture always used.
// Without incremental verification configured every call is a full walk, as before.
func (c *KeyorixCore) auditPostureReport(ctx context.Context) (*AuditVerifyReport, bool, error) {
	if !c.auditIncrementalEnabled() {
		r, err := c.AuditVerificationStatus(ctx)
		return r, false, err
	}

	// One refresh at a time: requests that arrive during a walk wait for it and
	// then read its result instead of starting their own.
	c.auditPostureMu.Lock()
	defer c.auditPostureMu.Unlock()

	now := c.now()
	prev := c.auditPosture
	if prev != nil && now.Sub(prev.attemptedAt) <= auditPostureRefreshAfter {
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

	log.Printf("compliance posture: audit chain refresh failed, keeping the previous check: %v", err)
	var kept *AuditVerifyReport
	if prev != nil {
		kept = prev.report
	} else if kept, err = c.AuditVerificationStatus(ctx); err != nil {
		return nil, false, err
	}
	if ctx.Err() == nil {
		// A request that went away says nothing about the check: do not let it
		// hold the retry back for the whole window.
		c.auditPosture = &auditPostureCache{report: kept, attemptedAt: now, refreshFailed: true}
	}
	return copyAuditReport(kept), true, nil
}

// copyAuditReport returns a shallow copy so callers cannot change the cached one.
func copyAuditReport(r *AuditVerifyReport) *AuditVerifyReport {
	cp := *r
	return &cp
}
