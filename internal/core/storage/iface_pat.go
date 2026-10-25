package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PATStore is the Storage slice for personal access tokens.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type PATStore interface {
	// Personal Access Token Management (ADR-027) — user-owned bearer credentials.
	CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error)
	ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error)
	// ListActivePersonalAccessTokens returns every non-revoked PAT across all users —
	// the deployment-wide view for token-hygiene auditing (stale / expired-but-active).
	ListActivePersonalAccessTokens(ctx context.Context) ([]*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error)
	RevokePersonalAccessToken(ctx context.Context, id uint) error
	// RevokeAllPersonalAccessTokensForUser revokes every active PAT for a user and returns
	// their token hashes (for immediate auth-cache eviction). Used on a password change/
	// reset so PATs die with the password.
	RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error)
	TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error
	// ListExpiredPATsByUser returns all non-revoked PATs for userID whose ExpiresAt
	// is in the past (expired but never explicitly revoked). Ordered newest first.
	ListExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]*models.PersonalAccessToken, error)
	// BulkRevokeExpiredPATsByUser revokes every non-revoked, expired PAT belonging to
	// userID (ExpiresAt < now) and returns their token hashes for cache eviction.
	BulkRevokeExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]string, error)
	// ListExpiringPATs returns every non-revoked PersonalAccessToken whose ExpiresAt
	// is non-nil and strictly before before (i.e. will expire before that instant).
	// Used by CheckTokenExpiry to find tokens approaching their deadline.
	ListExpiringPATs(ctx context.Context, before time.Time) ([]models.PersonalAccessToken, error)
}
