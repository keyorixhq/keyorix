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
// renewal is audited as secret.updated. truncated is true when more secrets matched
// the window than ListExpiringSecrets returned (#G24) — the sweep still renews the
// soonest-expiring ones first (storage orders by expiration ascending), but a caller
// with more matching secrets than the scan cap must know not every one was renewed.
func (c *KeyorixCore) ExtendExpiringSecrets(ctx context.Context, projectID uint, withinDays, newWindowDays int, actor string, actorID uint) (extended int, truncated bool, err error) {
	if projectID == 0 || actorID == 0 {
		return 0, false, fmt.Errorf("project ID and actor ID are required")
	}
	if newWindowDays <= 0 {
		newWindowDays = defaultExtendWindowDays
	}
	if newWindowDays > maxExpiringWindowDays {
		newWindowDays = maxExpiringWindowDays
	}
	newExpiry := c.now().Add(time.Duration(newWindowDays) * 24 * time.Hour)

	secrets, truncated, err := c.ListExpiringSecrets(ctx, projectID, withinDays)
	if err != nil {
		return 0, false, err
	}

	for _, s := range secrets {
		// Re-check per-secret write authorization (owner/share). The project-wide
		// secrets.write route gate is not sufficient on its own — the single-secret PUT
		// path enforces this too, so a caller who can't update a secret individually must
		// not be able to via the bulk op. Skip (don't abort) on denial.
		if _, err := c.EnforceSecretWritePermission(ctx, s.ID, actorID); err != nil {
			continue
		}
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
	return extended, truncated, nil
}
