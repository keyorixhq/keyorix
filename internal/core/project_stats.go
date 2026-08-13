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
	"github.com/keyorixhq/keyorix/internal/storage/models"
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

	// Truncated is true when the project has more live secrets than the 50 000-row
	// cap ListLiveSecretNamesByProject applied — TotalSecrets/ClassificationCounts
	// then reflect only the fetched sample, not the project's true secret count
	// (#G24: previously the storage layer's own truncation flag was discarded).
	Truncated bool `json:"truncated"`
}

// GetProjectStats computes statistics for a project by querying existing storage
// methods. All queries run sequentially; the function is cheap for typical
// projects (< a few thousand secrets).
func (c *KeyorixCore) GetProjectStats(ctx context.Context, projectID uint) (*ProjectStats, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}

	proj, err := c.storage.GetProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	now := c.now()
	out := &ProjectStats{
		ProjectID:   projectID,
		ProjectName: proj.Name,
		ComputedAt:  now,
	}

	// ── Secret counts via lightweight name rows ───────────────────────────────

	// ListLiveSecretNamesByProject returns one row per live secret with enough
	// metadata for classification bucketing and ID cross-referencing (anomaly
	// lookup). Cap at 50 000 to bound memory on very large projects.
	nameRows, truncated, err := c.storage.ListLiveSecretNamesByProject(ctx, []uint{projectID}, 50_000)
	if err != nil {
		return nil, fmt.Errorf("list project secret names: %w", err)
	}
	out.TotalSecrets = len(nameRows)
	out.Truncated = truncated
	classCounts, secretIDs := buildClassificationCounts(nameRows)
	out.ClassificationCounts = classCounts

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

	// Expiring in 30 days: expiration before now+30d includes already-expired;
	// subtract expired to get only the upcoming window.
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
	out.ExpiringIn30Days = max(0, int(expiring30Count)-out.ExpiredSecrets)
	out.ActiveSecrets = max(0, out.TotalSecrets-out.ExpiredSecrets)

	// ── Rotation health ───────────────────────────────────────────────────────

	statuses, err := c.GetRotationStatus(ctx, &projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("rotation status: %w", err)
	}
	out.RotationEnabled, out.OverdueRotation, out.LastRotationAt = aggregateRotationStats(statuses)

	// ── Unique accessors ──────────────────────────────────────────────────────

	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list project role assignments: %w", err)
	}
	out.UniqueAccessors = countUniqueUserAccessors(assignments)

	// ── Open anomalies ────────────────────────────────────────────────────────

	// ListAnomalyAlerts has no project filter; cross-reference with the project's
	// secret IDs to count only this project's unacknowledged alerts.
	ackFalse := false
	anomalies, err := c.storage.ListAnomalyAlerts(ctx, &ackFalse)
	if err != nil {
		return nil, fmt.Errorf("list anomaly alerts: %w", err)
	}
	out.OpenAnomalies = countProjectAnomalies(anomalies, secretIDs)

	return out, nil
}

// buildClassificationCounts returns a label→count map and a set of secret IDs
// from the given name rows. Labels default to "unclassified" when empty.
func buildClassificationCounts(rows []storage.SecretNameRow) (map[string]int, map[uint]bool) {
	counts := make(map[string]int, 4)
	ids := make(map[uint]bool, len(rows))
	for _, r := range rows {
		ids[r.ID] = true
		label := r.Classification
		if label == "" {
			label = "unclassified"
		}
		counts[label]++
	}
	return counts, ids
}

// aggregateRotationStats collapses rotation-status entries into per-project
// enabled/overdue counts and the most-recent rotation timestamp.
// Secrets covered by multiple overlapping policies are counted only once.
func aggregateRotationStats(statuses []*RotationStatusEntry) (enabled, overdue int, lastAt *time.Time) {
	seen := make(map[uint]bool)
	for _, s := range statuses {
		if seen[s.SecretID] {
			continue
		}
		seen[s.SecretID] = true
		enabled++
		if s.Status == RotationStatusOverdue {
			overdue++
		}
		if s.LastRotatedAt != nil {
			if lastAt == nil || s.LastRotatedAt.After(*lastAt) {
				ts := *s.LastRotatedAt
				lastAt = &ts
			}
		}
	}
	return enabled, overdue, lastAt
}

// countUniqueUserAccessors returns the number of distinct users with at least
// one direct role grant on the project.
func countUniqueUserAccessors(assignments []storage.RoleAssignment) int {
	seen := make(map[uint]bool)
	for _, a := range assignments {
		if a.PrincipalType == "user" && a.PrincipalID != 0 {
			seen[a.PrincipalID] = true
		}
	}
	return len(seen)
}

// countProjectAnomalies returns the number of alerts whose secret belongs to
// the given project (identified by secretIDs).
func countProjectAnomalies(alerts []models.AnomalyAlert, secretIDs map[uint]bool) int {
	n := 0
	for _, a := range alerts {
		if secretIDs[a.SecretNodeID] {
			n++
		}
	}
	return n
}
