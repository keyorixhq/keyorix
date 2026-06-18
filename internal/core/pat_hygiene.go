// pat_hygiene.go — deployment-wide personal-access-token hygiene: surface the
// non-revoked PATs that should probably be cleaned up — ones that have expired but
// were never revoked, and ones that have gone stale (unused for a long window). A
// long-lived bearer credential that is expired-but-active or abandoned is exactly the
// kind of token sprawl an attacker reuses, so this gives an admin one place to find
// and revoke them. Parallels the stale-machine-identity and unused-secret hygiene
// views. Read-only; never returns a token hash or plaintext. Admin-scoped (route-gated).
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// defaultPATStaleAfter is the staleness window used when the caller passes none: a PAT
// unused (or, if never used, uncreated-against) for 90 days is flagged stale.
const defaultPATStaleAfter = 90 * 24 * time.Hour

// PATHygieneEntry is one flagged token plus why it was flagged. The embedded token
// carries only metadata; callers must not surface its TokenHash.
type PATHygieneEntry struct {
	Token   *models.PersonalAccessToken
	Expired bool // ExpiresAt is in the past (but the token was never revoked)
	Stale   bool // not used within the staleness window (never-used counts from creation)
}

// ListPATHygiene returns the non-revoked PATs that are expired-but-active or stale
// (unused for longer than staleAfter; a never-used token counts from its creation).
// Healthy tokens are omitted. Newest-created first (the storage order is preserved).
func (c *KeyorixCore) ListPATHygiene(ctx context.Context, staleAfter time.Duration) ([]PATHygieneEntry, error) {
	if staleAfter <= 0 {
		staleAfter = defaultPATStaleAfter
	}
	tokens, err := c.storage.ListActivePersonalAccessTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	now := c.now()
	cutoff := now.Add(-staleAfter)

	var out []PATHygieneEntry
	for _, t := range tokens {
		expired := t.ExpiresAt != nil && t.ExpiresAt.Before(now)

		last := t.CreatedAt
		if t.LastUsedAt != nil {
			last = *t.LastUsedAt
		}
		stale := last.Before(cutoff)

		if expired || stale {
			out = append(out, PATHygieneEntry{Token: t, Expired: expired, Stale: stale})
		}
	}
	return out, nil
}
