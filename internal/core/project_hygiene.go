// project_hygiene.go — a project's security-hygiene posture at a glance: one call that
// counts the cleanup signals already computed individually elsewhere — secrets whose
// owner departed ([[secret_orphaned]]), secrets unused for a long window, secrets
// expiring/expired, and stale machine identities ([[machine_identities]]). Returns
// COUNTS only (no names or values), so it is safe to surface broadly and cheap to poll
// for a dashboard. Project-scoped (route-gated secrets.read).
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ProjectHygiene is the count of each cleanup signal for a project.
type ProjectHygiene struct {
	OrphanedSecrets        int `json:"orphaned_secrets"`
	UnusedSecrets          int `json:"unused_secrets"`
	ExpiringSecrets        int `json:"expiring_secrets"` // expiring within the window, or already expired
	StaleMachineIdentities int `json:"stale_machine_identities"`
	RotationOverdue        int `json:"rotation_overdue"` // secrets past their rotation policy's interval
}

// Hygiene-summary default windows (days). Each is overridable by the caller.
const (
	defaultHygieneUnusedDays   = 90
	defaultHygieneExpiringDays = 30
	defaultHygieneStaleMIDays  = 90
)

// ProjectHygieneSummary tallies the project's outstanding hygiene signals. The windows
// (in days) default when non-positive. Counts only — never names or values.
func (c *KeyorixCore) ProjectHygieneSummary(ctx context.Context, projectID uint, unusedDays, expiringDays, staleMIDays int) (*ProjectHygiene, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}
	if unusedDays <= 0 {
		unusedDays = defaultHygieneUnusedDays
	}
	if expiringDays <= 0 {
		expiringDays = defaultHygieneExpiringDays
	}
	if staleMIDays <= 0 {
		staleMIDays = defaultHygieneStaleMIDays
	}

	out := &ProjectHygiene{}

	orphaned, err := c.storage.ListOrphanedSecrets(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("orphaned secrets: %w", err)
	}
	out.OrphanedSecrets = len(orphaned)

	unused, err := c.UnusedSecrets(ctx, &projectID, nil, unusedDays)
	if err != nil {
		return nil, fmt.Errorf("unused secrets: %w", err)
	}
	out.UnusedSecrets = len(unused)

	// Expiring/expired: count secrets with an expiration before now+window. PageSize 1
	// keeps it a count query — we only read the total.
	cutoff := c.now().Add(time.Duration(expiringDays) * 24 * time.Hour)
	_, expiring, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID, ExpiresBefore: &cutoff, Page: 1, PageSize: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("expiring secrets: %w", err)
	}
	out.ExpiringSecrets = int(expiring)

	staleMI, err := c.ListStaleMachineIdentities(ctx, projectID, time.Duration(staleMIDays)*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("stale machine identities: %w", err)
	}
	out.StaleMachineIdentities = len(staleMI)

	// Secrets past their rotation policy's interval (reuses the rotation-status eval).
	statuses, err := c.GetRotationStatus(ctx, &projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("rotation status: %w", err)
	}
	for _, s := range statuses {
		if s.Status == RotationStatusOverdue {
			out.RotationOverdue++
		}
	}

	return out, nil
}
