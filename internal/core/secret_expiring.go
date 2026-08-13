// secret_expiring.go — list a project's secrets that are expiring (or already expired)
// within a window, soonest-first, so an operator can renew or rotate them before they
// lapse. The project hygiene summary ([[project_hygiene]]) counts these; this returns
// the actual secrets to act on. Read-only and metadata-only — never a value.
// Project-scoped (route-gated secrets.read).
package core

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	defaultExpiringWindowDays = 30
	maxExpiringWindowDays     = 3650
	expiringScanPageSize      = 500
)

// ListExpiringSecrets returns the project's secrets whose expiration falls before
// now+window (already-expired included), soonest-first. `withinDays` is clamped to
// [1, maxExpiringWindowDays]; non-positive falls back to the default. Metadata only.
// truncated is true when more matching secrets exist than expiringScanPageSize —
// the storage layer orders by expiration ascending before applying the cap (#G24),
// so a truncated result is still correctly prioritized (the N soonest-expiring,
// not an arbitrary N), but callers must still know it isn't the complete set.
func (c *KeyorixCore) ListExpiringSecrets(ctx context.Context, projectID uint, withinDays int) (secrets []*models.SecretNode, truncated bool, err error) {
	if projectID == 0 {
		return nil, false, fmt.Errorf("project ID is required")
	}
	if withinDays <= 0 {
		withinDays = defaultExpiringWindowDays
	}
	if withinDays > maxExpiringWindowDays {
		withinDays = maxExpiringWindowDays
	}
	cutoff := c.now().Add(time.Duration(withinDays) * 24 * time.Hour)

	secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID:     &projectID,
		ExpiresBefore: &cutoff,
		Page:          1,
		PageSize:      expiringScanPageSize,
	})
	if err != nil {
		return nil, false, fmt.Errorf("%w", err)
	}
	// Soonest expiration first (already-expired lead). Storage now orders by
	// expiration ASC too, so this is a stable re-affirmation, not the sole
	// ordering guarantee. A returned row always has a non-nil Expiration (the
	// filter requires it), but guard defensively.
	sort.SliceStable(secrets, func(i, j int) bool {
		if secrets[i].Expiration == nil || secrets[j].Expiration == nil {
			return secrets[j].Expiration != nil
		}
		return secrets[i].Expiration.Before(*secrets[j].Expiration)
	})
	return secrets, int64(len(secrets)) < total, nil
}
