package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// minRetentionDays is the minimum allowed retention window for a purge.
// Enforced to prevent accidental mass-deletion of recent audit events.
const minRetentionDays = 7

// AuditLogRetentionConfig controls how old an audit event must be before it
// can be purged. RetentionDays of 0 means "keep forever" (no purge).
type AuditLogRetentionConfig struct {
	RetentionDays int // 0 = no purge
}

// PurgeAuditLogsResult summarises how many rows were deleted.
type PurgeAuditLogsResult struct {
	DeletedCount int64
	CutoffTime   time.Time
}

// PurgeAuditLogs deletes audit events older than cfg.RetentionDays days.
// Returns ErrInvalidAuditRetentionDays if RetentionDays < minRetentionDays (7).
// A minimum of 7 days is enforced to prevent accidental mass-deletion.
func (c *KeyorixCore) PurgeAuditLogs(ctx context.Context, cfg AuditLogRetentionConfig) (*PurgeAuditLogsResult, error) {
	if cfg.RetentionDays < minRetentionDays {
		return nil, fmt.Errorf("%w: retention_days must be at least %d (got %d)",
			ErrInvalidAuditRetentionDays, minRetentionDays, cfg.RetentionDays)
	}

	cutoff := c.now().UTC().AddDate(0, 0, -cfg.RetentionDays)
	n, err := c.storage.DeleteAuditLogsBefore(ctx, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to purge audit logs: %w", err)
	}

	sysCtx := WithActorType(ctx, ActorTypeSystem)
	c.writeAuditEvent(sysCtx, "system.audit_purge", nil, nil,
		fmt.Sprintf("audit log retention purge: removed %d event(s) older than %d days (cutoff %s)",
			n, cfg.RetentionDays, cutoff.Format(time.RFC3339)))

	return &PurgeAuditLogsResult{DeletedCount: n, CutoffTime: cutoff}, nil
}

// nis2RetentionDays is the audit-log retention window NIS2 (and DORA) expect an
// operator to be able to demonstrate: 12 months.
const nis2RetentionDays = 365

// RetentionPolicyUnlimited is reported on every coverage response: Keyorix
// never purges, caps, or time-limits audit events — retention is bounded only
// by the operator's PostgreSQL.
const RetentionPolicyUnlimited = "unlimited"

// AuditRetentionCoverage describes how far back the audit trail demonstrably
// reaches. It turns the "we retain everything" claim into an auditable figure:
// an operator or buyer-security-review can read the oldest event and confirm
// the trail spans the NIS2-mandated 12 months.
type AuditRetentionCoverage struct {
	// RetentionPolicy is always "unlimited" — Keyorix applies no audit cap.
	RetentionPolicy string `json:"retention_policy"`
	// TotalEvents is the number of audit events currently stored.
	TotalEvents int64 `json:"total_events"`
	// OldestEvent / NewestEvent bound the trail. Nil when no events exist yet.
	OldestEvent *time.Time `json:"oldest_event"`
	NewestEvent *time.Time `json:"newest_event"`
	// CoverageDays is how far back the trail reaches from now (now − oldest),
	// i.e. the age of the earliest retained event. 0 when there are no events.
	CoverageDays int `json:"coverage_days"`
	// MeetsNIS2TwelveMonth is true once the trail's earliest event is at least
	// 12 months old, i.e. there is genuine 12-month history to inspect today.
	// A young deployment reads false without any retention deficiency — the
	// policy is still unlimited; there simply is not yet 12 months of history.
	MeetsNIS2TwelveMonth bool `json:"meets_nis2_12_month"`
}

// AuditRetentionCoverage reports the audit trail's retention coverage: total
// event count, the oldest/newest event, how many days back the trail reaches,
// and whether that demonstrably covers the NIS2 12-month window. Backs the
// compliance/retention inspector — see docs/compliance/AUDIT-LOG-PROVISIONS.md.
func (c *KeyorixCore) AuditRetentionCoverage(ctx context.Context) (*AuditRetentionCoverage, error) {
	stats, err := c.storage.AuditRetentionStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to compute audit retention coverage: %w", err)
	}

	cov := &AuditRetentionCoverage{
		RetentionPolicy: RetentionPolicyUnlimited,
		TotalEvents:     stats.TotalEvents,
		OldestEvent:     stats.Oldest,
		NewestEvent:     stats.Newest,
	}
	if stats.Oldest != nil {
		days := int(c.now().Sub(*stats.Oldest).Hours() / 24)
		if days < 0 {
			days = 0
		}
		cov.CoverageDays = days
		cov.MeetsNIS2TwelveMonth = days >= nis2RetentionDays
	}
	return cov, nil
}

// VerifyAuditChain re-walks the tamper-evidence hash chain (ADR-029) and reports
// whether the audit trail is intact. When a signing key is configured, it also
// verifies the live chain against the latest signed checkpoint — adding on-box
// detection of tail-truncation / genesis re-seed that the bare re-walk cannot
// catch. Backs GET /api/v1/audit/verify — see
// docs/adr-029-audit-log-tamper-evidence.md.
func (c *KeyorixCore) VerifyAuditChain(ctx context.Context) (*storage.AuditChainVerification, error) {
	v, err := c.storage.VerifyAuditChain(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit chain: %w", err)
	}
	if err := c.enforceAuditCheckpoint(ctx, v); err != nil {
		return nil, fmt.Errorf("failed to verify audit checkpoint: %w", err)
	}
	return v, nil
}
