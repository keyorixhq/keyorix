package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SetupTokenStore is the Storage slice for one-time setup tokens.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type SetupTokenStore interface {
	// Setup Token Management (ADR-028) — single-use, hashed-at-rest credential-delivery tokens.
	CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error)
	// GetSetupTokenByHash is the consumption lookup (indexed equality on token_hash).
	GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error)
	// GetSetupTokenByID looks up a setup token by primary key. Only ever called
	// from KeyorixCore.ExpireSetupTokenByID (#1622) to resolve purpose/subject
	// detail for an explicit (non-lazy-read) expiry's audit write --
	// ExpireSetupTokenByID's own doc has more on why that method (and so this
	// one) has zero production callers today.
	GetSetupTokenByID(ctx context.Context, id uint) (*models.SetupToken, error)
	// SupersedeActiveSetupTokens flips every active token for (purpose, email) to
	// superseded, so reissuing ("resend") atomically kills the prior link.
	// projectID, when non-nil, additionally restricts the flip to tokens whose
	// InvitationID belongs to that project (via project_invitations) — so a
	// project-scoped invitation_accept reissue only supersedes that SAME project's
	// pending invite to the address, not an unrelated project's (CORE-INVITATIONS-003).
	// A nil projectID preserves the original (purpose, email)-only scope, which
	// callers with no project dimension (global invites, account_setup,
	// password_reset_link) still rely on.
	SupersedeActiveSetupTokens(ctx context.Context, purpose, email string, projectID *uint) error
	// MarkSetupTokenConsumed transitions active → consumed only if the token is still
	// active, stamping consumedAt. It reports whether the transition happened, so a
	// concurrent replay (state already consumed/expired/superseded) is rejected.
	MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error)
	// MarkSetupTokenExpired transitions active → expired (lazy expiry on read).
	MarkSetupTokenExpired(ctx context.Context, id uint) error
	// CountSetupTokensSince counts tokens minted for (purpose, email) since a cutoff,
	// backing resend throttling / daily caps.
	CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error)
}
