package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SystemStore is the Storage slice for health, statistics, snapshots, usage and billing, system metadata, recovery key.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type SystemStore interface {
	// Stats Snapshots
	SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error
	GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error)

	// SaveDeploymentStatsSnapshot persists a deployment-wide stats snapshot.
	// Call once per UTC day from GetDashboardStats when admin stats are available.
	SaveDeploymentStatsSnapshot(ctx context.Context, snap *models.DeploymentStatsSnapshot) error

	// GetPreviousDeploymentStatsSnapshot returns the most recent deployment stats
	// snapshot that is older than 20 hours (so a new snapshot saved today doesn't
	// immediately compare against itself).  Returns nil, nil if none exists.
	GetPreviousDeploymentStatsSnapshot(ctx context.Context) (*models.DeploymentStatsSnapshot, error)

	// Compliance Posture Snapshots
	SaveCompliancePostureSnapshot(ctx context.Context, snap *models.CompliancePostureSnapshot) error
	// GetPreviousCompliancePostureSnapshot returns the most recent snapshot whose
	// snapshot_date is strictly before today's UTC midnight (i.e., from a prior
	// calendar day), to avoid same-day self-comparison.
	// Returns nil, nil when no prior snapshot exists.
	GetPreviousCompliancePostureSnapshot(ctx context.Context, before time.Time) (*models.CompliancePostureSnapshot, error)
	// ListCompliancePostureSnapshots returns snapshots ordered by snapshot_date
	// descending (most recent first). limit ≤ 0 returns the default cap (90 rows).
	ListCompliancePostureSnapshots(ctx context.Context, limit int) ([]*models.CompliancePostureSnapshot, error)

	// Credential Hygiene Trend Snapshots — daily counts of stale/expired PATs and
	// stale machine credentials for per-day trend queries.
	//
	// SaveHygieneTrendSnapshot upserts a snapshot for the given UTC calendar day
	// (first write creates; same-day re-run overwrites in place). Used by
	// RecordHygieneTrendPoint and the daily hygiene scheduler.
	SaveHygieneTrendSnapshot(ctx context.Context, snap *models.HygieneTrendSnapshot) error
	// ListHygieneTrendSnapshots returns up to `days` snapshots ordered by
	// snapshot_date DESC (newest first). Used by GetHygieneTrends.
	ListHygieneTrendSnapshots(ctx context.Context, days int) ([]*models.HygieneTrendSnapshot, error)
	// CountStalePATs returns the count of non-revoked PersonalAccessTokens where
	// ExpiresAt IS NULL OR ExpiresAt > now (active), AND
	// (LastUsedAt IS NULL OR LastUsedAt < threshold) — stale but not expired.
	CountStalePATs(ctx context.Context, threshold time.Time) (int, error)
	// CountExpiredPATs returns the count of non-revoked PersonalAccessTokens where
	// ExpiresAt IS NOT NULL AND ExpiresAt < now (expired but never revoked).
	CountExpiredPATs(ctx context.Context) (int, error)
	// CountStaleMachineCredentials returns the count of distinct machine identities
	// (active state) where all their credentials are either never used or were
	// last used before threshold (i.e. the machine identity is "stale").
	CountStaleMachineCredentials(ctx context.Context, threshold time.Time) (int, error)
	// GetSystemMetadata returns the value stored for key; found is false when the key
	// has never been set. A small singleton key/value store for server-managed state.
	GetSystemMetadata(ctx context.Context, key string) (value string, found bool, err error)
	// SetSystemMetadata upserts a system-metadata key/value (last write wins).
	SetSystemMetadata(ctx context.Context, key, value string) error
	// GetRecoveryKeyRecord returns the local admin recovery key's verifier
	// record (docs/design-b2-recover-admin.md §2); found is false on an
	// install that predates this feature or has never generated one.
	GetRecoveryKeyRecord(ctx context.Context) (record *models.RecoveryKeyRecord, found bool, err error)
	// SetRecoveryKeyRecord upserts the singleton recovery-key record —
	// generation and rotation are the same call; the caller sets KeyVersion
	// (and RotatedAt on rotation). Exactly one row ever exists.
	SetRecoveryKeyRecord(ctx context.Context, record *models.RecoveryKeyRecord) error

	// Health and Maintenance
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*StorageStats, error)

	// GetProjectUsageStats returns per-project usage stats for the given projects
	// over the past windowDays days. Passing nil for projectIDs returns stats for
	// ALL projects. The result may omit projects with zero activity and zero secrets.
	GetProjectUsageStats(ctx context.Context, projectIDs []uint, windowDays int) ([]ProjectUsageStat, error)

	// GetBillingReport returns per-project usage stats for the half-open interval [from, to).
	// If projectIDs is non-empty, only those projects are included; otherwise all projects
	// with any activity in the window (or existing secrets) are included.
	GetBillingReport(ctx context.Context, from, to time.Time, projectIDs []uint) (*BillingReport, error)
}
