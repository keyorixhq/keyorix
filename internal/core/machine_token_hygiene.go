// machine_token_hygiene.go — deployment-wide machine-token hygiene: the non-revoked
// machine-identity credentials that should probably be cleaned up — expired-but-never-
// revoked, or stale (unused for a long window). The non-human counterpart to PAT
// hygiene ([[pat_hygiene]]): an abandoned or expired machine token is the same kind of
// reusable credential an attacker prizes. Read-only; never returns a token hash.
// Route-gated on audit.read (not the universal system_viewer baseline; see #274) —
// discloses credential names/prefixes/expiry deployment-wide.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// defaultMachineTokenStaleAfter is the staleness window used when none is given.
const defaultMachineTokenStaleAfter = 90 * 24 * time.Hour

// MachineTokenHygieneEntry is one flagged machine credential plus why. The embedded
// credential carries only metadata; callers must not surface its TokenHash.
type MachineTokenHygieneEntry struct {
	Credential *models.MachineIdentityCredential
	Expired    bool // ExpiresAt is in the past (but the token was never revoked)
	Stale      bool // not used within the staleness window (never-used counts from creation)
}

// ListMachineTokenHygiene returns the non-revoked machine credentials that are
// expired-but-active or stale (unused beyond staleAfter; a never-used token counts
// from creation). Healthy tokens are omitted. staleAfter defaults when non-positive.
func (c *KeyorixCore) ListMachineTokenHygiene(ctx context.Context, staleAfter time.Duration) ([]MachineTokenHygieneEntry, error) {
	if staleAfter <= 0 {
		staleAfter = defaultMachineTokenStaleAfter
	}
	creds, err := c.storage.ListActiveMachineIdentityCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list machine credentials: %w", err)
	}
	now := c.now()
	cutoff := now.Add(-staleAfter)

	var out []MachineTokenHygieneEntry
	for _, t := range creds {
		expired := t.ExpiresAt != nil && t.ExpiresAt.Before(now)

		last := t.CreatedAt
		if t.LastUsedAt != nil {
			last = *t.LastUsedAt
		}
		stale := last.Before(cutoff)

		if expired || stale {
			out = append(out, MachineTokenHygieneEntry{Credential: t, Expired: expired, Stale: stale})
		}
	}
	return out, nil
}
