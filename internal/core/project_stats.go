// project_stats.go — rich per-project statistics for dashboards and the CLI.
//
// GET /api/v1/projects/{id}/stats
// keyorix project stats <name>
//
// Derives all statistics from existing data — no new DB model. Counts are
// computed sequentially from the storage layer; no net-new queries are added
// beyond what the existing hygiene/rotation/anomaly paths already use.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ProjectStats holds rich per-project statistics for a dashboard or CLI summary.
type ProjectStats struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`

	// Secret counts
	TotalSecrets     int `json:"total_secrets"`
	ActiveSecrets    int `json:"active_secrets"`
	ExpiredSecrets   int `json:"expired_secrets"`     // expiration < now
	ExpiringIn30Days int `json:"expiring_in_30_days"` // expiration in [now, now+30d)

	// Rotation health
	RotationEnabled int        `json:"rotation_enabled"` // secrets covered by an active rotation policy
	OverdueRotation int        `json:"overdue_rotation"` // of those, past their rotation interval
	LastRotationAt  *time.Time `json:"last_rotation_at,omitempty"`

	// Access
	UniqueAccessors int `json:"unique_accessors"` // distinct users with a project-scoped role grant
	OpenAnomalies   int `json:"open_anomalies"`   // unacknowledged anomaly alerts for project secrets

	// ClassificationCounts is a breakdown by data-sensitivity label,
	// e.g. {"confidential":3,"internal":8,"unclassified":2}.
	ClassificationCounts map[string]int `json:"classification_counts"`

	ComputedAt time.Time `json:"computed_at"`
}

// GetProjectStats computes statistics for a project by querying existing storage
// methods. All queries run sequentially; the function is cheap for typical
// projects (< a few thousand secrets).
func (c *KeyorixCore) GetProjectStats(ctx context.Context, projectID uint) (*ProjectStats, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}

	// Resolve project name.
	proj, err := c.storage.GetProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	now := c.now()
	out := &ProjectStats{
		ProjectID:            projectID,
		ProjectName:          proj.Name,
		ClassificationCounts: make(map[string]int),
		ComputedAt:           now,
	}

	// ── Secret counts via lightweight name rows ───────────────────────────────

	// ListLiveSecretNamesByProject returns one row per live secret with enough
	// metadata for classification bucketing and ID cross-referencing (anomaly
	// lookup). Cap at 50 000 to bound memory on very large projects.
	nameRows, _, err := c.storage.ListLiveSecretNamesByProject(ctx, []uint{projectID}, 50_000)
	if err != nil {
		return nil, fmt.Errorf("list project secret names: %w", err)
	}

	out.TotalSecrets = len(nameRows)
	projectSecretIDs := make(map[uint]bool, len(nameRows))
	for _, r := range nameRows {
		projectSecretIDs[r.ID] = true
		label := r.Classification
		if label == "" {
			label = "unclassified"
		}
		out.ClassificationCounts[label]++
	}

	// Expired: secrets whose expiration is before now.
	isSecret := true
	expiredCutoff := now
	_, expiredCount, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID:     &projectID,
		IsSecret:      &isSecret,
		ExpiresBefore: &expiredCutoff,
		Page:          1,
		PageSize:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("expired secrets count: %w", err)
	}
	out.ExpiredSecrets = int(expiredCount)

	// Expiring in 30 days: secrets whose expiration is before now+30d (includes
	// already-expired rows); subtract expired to get the upcoming window.
	expiring30Cutoff := now.Add(30 * 24 * time.Hour)
	_, expiring30Count, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID:     &projectID,
		IsSecret:      &isSecret,
		ExpiresBefore: &expiring30Cutoff,
		Page:          1,
		PageSize:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("expiring-in-30d count: %w", err)
	}
	out.ExpiringIn30Days = int(expiring30Count) - out.ExpiredSecrets
	if out.ExpiringIn30Days < 0 {
		out.ExpiringIn30Days = 0
	}

	out.ActiveSecrets = out.TotalSecrets - out.ExpiredSecrets
	if out.ActiveSecrets < 0 {
		out.ActiveSecrets = 0
	}

	// ── Rotation health ───────────────────────────────────────────────────────

	statuses, err := c.GetRotationStatus(ctx, &projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("rotation status: %w", err)
	}
	// Deduplicate by SecretID: a secret covered by multiple overlapping policies
	// must not inflate RotationEnabled or OverdueRotation.
	seenRotation := make(map[uint]bool)
	var latestRotation *time.Time
	for _, s := range statuses {
		if seenRotation[s.SecretID] {
			continue
		}
		seenRotation[s.SecretID] = true
		out.RotationEnabled++
		if s.Status == RotationStatusOverdue {
			out.OverdueRotation++
		}
		if s.LastRotatedAt != nil {
			if latestRotation == nil || s.LastRotatedAt.After(*latestRotation) {
				ts := *s.LastRotatedAt
				latestRotation = &ts
			}
		}
	}
	out.LastRotationAt = latestRotation

	// ── Unique accessors ──────────────────────────────────────────────────────

	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list project role assignments: %w", err)
	}
	uniqueUsers := make(map[uint]bool)
	for _, a := range assignments {
		if a.PrincipalType == "user" && a.PrincipalID != 0 {
			uniqueUsers[a.PrincipalID] = true
		}
	}
	out.UniqueAccessors = len(uniqueUsers)

	// ── Open anomalies ────────────────────────────────────────────────────────

	// ListAnomalyAlerts has no project filter; cross-reference with project's
	// secret IDs to count only this project's unacknowledged alerts.
	ackFalse := false
	anomalies, err := c.storage.ListAnomalyAlerts(ctx, &ackFalse)
	if err != nil {
		return nil, fmt.Errorf("list anomaly alerts: %w", err)
	}
	for _, a := range anomalies {
		if projectSecretIDs[a.SecretNodeID] {
			out.OpenAnomalies++
		}
	}

	return out, nil
}
