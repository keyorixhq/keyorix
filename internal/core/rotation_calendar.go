package core

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RotationCalendarEntry is a single secret's computed rotation event falling
// within a requested date window.
type RotationCalendarEntry struct {
	SecretID       uint       `json:"secret_id"`
	SecretName     string     `json:"secret_name"`
	ProjectID      uint       `json:"project_id"`
	EnvironmentID  uint       `json:"environment_id"`
	PolicyID       uint       `json:"policy_id"`
	PolicyName     string     `json:"policy_name"`
	IntervalDays   int        `json:"interval_days"`
	LastRotatedAt  *time.Time `json:"last_rotated_at,omitempty"`
	NextRotationAt time.Time  `json:"next_rotation_at"`
	// DaysUntilDue is positive when the rotation is in the future relative to now,
	// and negative (or zero) when the rotation is overdue.
	DaysUntilDue int  `json:"days_until_due"`
	IsOverdue    bool `json:"is_overdue"`
}

// GetRotationCalendar returns every policy-covered secret whose NextRotationAt
// falls within [from, to] (inclusive), sorted by NextRotationAt ascending.
// NextRotationAt is computed as LastRotatedAt + IntervalDays, falling back to
// CreatedAt + IntervalDays for secrets that have never been rotated.
// from must not be after to.
//
// projectID/environmentID are an optional scoping filter, mirroring
// GetRotationStatus/EvaluateRotationPolicies: nil/nil returns the deployment-wide
// calendar (every project, every tenant) as before; a non-nil projectID confines
// the result to that project's policies (via ListRotationPolicies) and — via
// policyAppliesToEnv + scopedPolicySecrets — a non-nil environmentID further
// confines it to that environment, so a caller authorized only at project (or
// environment) scope can request just their own slice instead of the full
// deployment-wide detail. The HTTP route requires global secrets.read when no
// filter is supplied and project/environment-scoped secrets.read when one is,
// via RequireScopedPermission(ScopeFromQuery).
func (c *KeyorixCore) GetRotationCalendar(ctx context.Context, from, to time.Time, projectID, environmentID *uint) ([]RotationCalendarEntry, error) {
	if from.After(to) {
		return nil, fmt.Errorf("from must not be after to")
	}

	policies, err := c.storage.ListRotationPolicies(ctx, projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("rotation calendar: list policies: %w", err)
	}

	now := c.now()
	var entries []RotationCalendarEntry

	for _, policy := range policies {
		if !policy.IsActive || !policyAppliesToEnv(policy, environmentID) {
			continue
		}
		secrets, err := c.scopedPolicySecrets(ctx, policy, environmentID)
		if err != nil {
			return nil, fmt.Errorf("rotation calendar: policy %d secrets: %w", policy.ID, err)
		}
		entries = appendCalendarEntries(entries, secrets, policy, now, from, to)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].NextRotationAt.Before(entries[j].NextRotationAt)
	})

	return entries, nil
}

func appendCalendarEntries(
	entries []RotationCalendarEntry,
	secrets []*models.SecretNode,
	policy *models.RotationPolicy,
	now, from, to time.Time,
) []RotationCalendarEntry {
	for _, s := range secrets {
		baseline := s.CreatedAt
		if s.LastRotatedAt != nil {
			baseline = *s.LastRotatedAt
		}
		next := baseline.AddDate(0, 0, policy.IntervalDays)
		if next.Before(from) || next.After(to) {
			continue
		}
		daysUntil := int(next.Sub(now).Hours() / 24)
		entries = append(entries, RotationCalendarEntry{
			SecretID:       s.ID,
			SecretName:     s.Name,
			ProjectID:      s.ProjectID,
			EnvironmentID:  s.EnvironmentID,
			PolicyID:       policy.ID,
			PolicyName:     policy.Name,
			IntervalDays:   policy.IntervalDays,
			LastRotatedAt:  s.LastRotatedAt,
			NextRotationAt: next,
			DaysUntilDue:   daysUntil,
			IsOverdue:      next.Before(now),
		})
	}
	return entries
}
