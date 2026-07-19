// local_role_expiry.go — LocalStorage implementation of ListExpiringUserRoles,
// used by core.CheckRoleExpiry to find JIT role grants approaching their deadline.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListExpiringUserRoles returns every UserRole whose ExpiresAt is non-nil and
// before the given cutoff. Grants that have already expired (ExpiresAt in the
// past) are included so the critical-window check can catch them too.
func (ls *LocalStorage) ListExpiringUserRoles(ctx context.Context, before time.Time) ([]models.UserRole, error) {
	var grants []models.UserRole
	return grants, ls.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at < ?", before).
		Find(&grants).Error
}
