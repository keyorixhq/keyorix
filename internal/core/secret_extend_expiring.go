// secret_extend_expiring.go — bulk expiry renewal: push out the expiration of every
// secret in a project that is expiring (or already expired) within a window, in one
// call. The expiring list ([[secret_expiring]]) and the hygiene summary surface these;
// this is the remediation — renew them before they lapse instead of editing each by
// hand. Never reads or changes a secret's value. Project-scoped (route-gated
// secrets.write). Parallels the bulk reassign-owner / suspend-all operations.
package core

import (
	"context"
	"fmt"
	"time"
)

const defaultExtendWindowDays = 90

// ExtendExpiringSecrets sets a new expiration of now+newWindowDays on every secret in
// the project expiring within withinDays (already-expired included), and returns the
// number extended. A secret whose current expiration is already later than the new one
// is left untouched (this only ever pushes expiry out, never pulls it in). Best-effort:
// a per-secret update failure is skipped so one bad row doesn't abort the rest. Each
// renewal is audited as secret.updated.
func (c *KeyorixCore) ExtendExpiringSecrets(ctx context.Context, projectID uint, withinDays, newWindowDays int, actor string, actorID uint) (int, error) {
	if projectID == 0 || actorID == 0 {
		return 0, fmt.Errorf("project ID and actor ID are required")
	}
	if newWindowDays <= 0 {
		newWindowDays = defaultExtendWindowDays
	}
	if newWindowDays > maxExpiringWindowDays {
		newWindowDays = maxExpiringWindowDays
	}
	newExpiry := c.now().Add(time.Duration(newWindowDays) * 24 * time.Hour)

	secrets, err := c.ListExpiringSecrets(ctx, projectID, withinDays)
	if err != nil {
		return 0, err
	}

	extended := 0
	for _, s := range secrets {
		// Only push expiry out, never in — skip a secret already dated past the new window.
		if s.Expiration != nil && !s.Expiration.Before(newExpiry) {
			continue
		}
		s.Expiration = &newExpiry
		if _, err := c.storage.UpdateSecret(ctx, s); err != nil {
			continue // best-effort: skip per-secret failures, keep going
		}
		c.LogSecretUpdatedWithProject(ctx, actorID, s.ID, projectID, actor, s.Name, "", "")
		extended++
	}
	return extended, nil
}
