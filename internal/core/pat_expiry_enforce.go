// pat_expiry_enforce.go — PAT expiry enforcement helpers (ADR-027).
//
// IsPATExpired is a pure, clock-injectable predicate used both on the auth hot
// path (ValidatePATToken) and in tests.  emitPATExpiredNotification fires a
// best-effort in-app notification so the owner knows to clean up.
// ListExpiredOwnPATs / BulkRevokeExpiredOwnPATs give the user a self-service
// way to enumerate and retire their dead tokens.
package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrPATExpired is returned by ValidatePATToken when the presented token has
// passed its ExpiresAt.  The caller (auth middleware) surfaces it as a 401.
var ErrPATExpired = errors.New("token expired")

// ErrPATRevoked is returned by ValidatePATToken/CurrentPATRestriction when the
// presented token has been revoked.  The caller (auth middleware) surfaces it
// as a 401.
var ErrPATRevoked = errors.New("token revoked")

// IsPATExpired reports whether pat has a non-nil ExpiresAt that is in the past
// relative to now.  It is a pure function — injectable for testing.
func IsPATExpired(pat *models.PersonalAccessToken, now time.Time) bool {
	return pat.ExpiresAt != nil && now.After(*pat.ExpiresAt)
}

// emitPATExpiredNotification creates a best-effort in-app notification for the
// PAT owner when an expired token is presented at the auth boundary.  Errors
// are swallowed so a failed insert never blocks the auth rejection.
func (c *KeyorixCore) emitPATExpiredNotification(ctx context.Context, pat *models.PersonalAccessToken) {
	c.notifyWithSeverity(
		ctx,
		pat.UserID,
		NotificationPATExpiredUsed,
		"Expired PAT presented",
		fmt.Sprintf("Personal access token '%s' has expired and was rejected. Revoke or replace it.", pat.Name),
		nil,
		"/account/tokens",
		models.NotificationSeverityWarning,
	)
}

// ListExpiredOwnPATs returns the caller's own non-revoked PATs whose ExpiresAt
// is in the past.
func (c *KeyorixCore) ListExpiredOwnPATs(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.ListExpiredPATsByUser(ctx, userID, c.now())
}

// BulkRevokeExpiredOwnPATs revokes all the caller's non-revoked, expired PATs
// and returns the revoked token hashes for auth-cache eviction.
func (c *KeyorixCore) BulkRevokeExpiredOwnPATs(ctx context.Context, userID uint) ([]string, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.BulkRevokeExpiredPATsByUser(ctx, userID, c.now())
}
