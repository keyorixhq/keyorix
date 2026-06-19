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
func (c *KeyorixCore) ListExpiringSecrets(ctx context.Context, projectID uint, withinDays int) ([]*models.SecretNode, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}
	if withinDays <= 0 {
		withinDays = defaultExpiringWindowDays
	}
	if withinDays > maxExpiringWindowDays {
		withinDays = maxExpiringWindowDays
	}
	cutoff := c.now().Add(time.Duration(withinDays) * 24 * time.Hour)

	secrets, _, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID:     &projectID,
		ExpiresBefore: &cutoff,
		Page:          1,
		PageSize:      expiringScanPageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	// Soonest expiration first (already-expired lead). A returned row always has a
	// non-nil Expiration (the filter requires it), but guard defensively.
	sort.SliceStable(secrets, func(i, j int) bool {
		if secrets[i].Expiration == nil || secrets[j].Expiration == nil {
			return secrets[j].Expiration != nil
		}
		return secrets[i].Expiration.Before(*secrets[j].Expiration)
	})
	return secrets, nil
}
