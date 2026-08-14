// local_dynamic.go — dynamic-secrets persistence (ADR-035): configs and the
// issued leases whose expiry drives the auto-revoke sweep.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error) {
	if err := ls.db.WithContext(ctx).Create(c).Error; err != nil {
		if isUniqueViolation(err) {
			// The unique index uniq_dynamic_secret_configs_project_env_name (#462) caught a
			// duplicate (project, environment, name) tuple — the only unique constraint on
			// this table, so a bare driver-message match (isUniqueViolation, shared with
			// CreateProjectMembership) is unambiguous here. Translate to the sentinel so
			// callers (CreateDynamicSecretConfig in internal/core) can surface a clean
			// validation error instead of a raw constraint-violation message.
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateDynamicSecretConfig, err)
		}
		return nil, err
	}
	return c, nil
}

func (ls *LocalStorage) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	var c models.DynamicSecretConfig
	if err := ls.db.WithContext(ctx).First(&c, id).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (ls *LocalStorage) ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error) {
	var cs []*models.DynamicSecretConfig
	q := ls.db.WithContext(ctx).Where("project_id = ?", projectID)
	if environmentID != 0 {
		q = q.Where("environment_id = ?", environmentID)
	}
	if err := q.Order("name").Find(&cs).Error; err != nil {
		return nil, err
	}
	return cs, nil
}

func (ls *LocalStorage) UpdateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) error {
	return ls.db.WithContext(ctx).Save(c).Error
}

// TransitionDynamicSecretConfigDisabled persists c's full row via a conditional
// UPDATE gated on the row's CURRENT disabled value still being fromDisabled (see
// the interface doc in internal/core/storage/interface.go for why this exists
// alongside — not instead of — GetDynamicSecretConfig/UpdateDynamicSecretConfig).
// Mirrors TransitionMachineIdentityState's `WHERE id = ? AND state = ?` +
// `Select("*")` shape exactly, so every field the caller mutated on c (Disabled,
// UpdatedAt, ...) is persisted in the same statement, not just a hardcoded
// column subset.
func (ls *LocalStorage) TransitionDynamicSecretConfigDisabled(ctx context.Context, c *models.DynamicSecretConfig, fromDisabled bool) (bool, error) {
	// #G42: the guard only checks `disabled`, so a concurrent DSN rotation or
	// classification change (UpdateDynamicSecretConfig, an unconditional Save
	// that doesn't touch `disabled`) still matches this WHERE clause. A
	// Select("*") here would silently revert that concurrent edit back to
	// this call's stale copy even though the enable/disable toggle itself is
	// legitimate. Whitelist only the columns this transition actually owns.
	res := ls.db.WithContext(ctx).Model(&models.DynamicSecretConfig{}).
		Where("id = ? AND disabled = ?", c.ID, fromDisabled).
		Select("Disabled", "UpdatedAt").
		Updates(c)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// CountDynamicSecretConfigsByClassification returns config counts keyed by
// classification label ("" = unclassified), install-wide, via a GROUP BY.
func (ls *LocalStorage) CountDynamicSecretConfigsByClassification(ctx context.Context) (map[string]int, error) {
	return countByClassification(ctx, ls.db, &models.DynamicSecretConfig{})
}

func (ls *LocalStorage) CreateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) (*models.DynamicSecretLease, error) {
	if err := ls.db.WithContext(ctx).Create(l).Error; err != nil {
		return nil, err
	}
	return l, nil
}

func (ls *LocalStorage) GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error) {
	var l models.DynamicSecretLease
	if err := ls.db.WithContext(ctx).Where("lease_id = ?", leaseID).First(&l).Error; err != nil {
		return nil, err
	}
	return &l, nil
}

func (ls *LocalStorage) ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error) {
	var ls2 []*models.DynamicSecretLease
	if err := ls.db.WithContext(ctx).Where("config_id = ?", configID).Order("issued_at desc").Limit(maxUnboundedListRows).Find(&ls2).Error; err != nil {
		return nil, err
	}
	return ls2, nil
}

func (ls *LocalStorage) UpdateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) error {
	return ls.db.WithContext(ctx).Save(l).Error
}

// CountActiveLeases returns the number of leases for a config that still hold a live
// credential upstream — status "active" AND "revoke_failed" (#411: a revoke_failed
// lease's earlier revoke attempt failed on the target, so its credential is still live,
// exactly the same "still live" reasoning ListExpiredActiveLeases documents above). An
// active-only count would let an attacker (or ordinary backend flakiness) force revokes
// to fail at issue time and silently exceed MaxActiveLeases forever, since every
// subsequent ceiling check would undercount the leftover live credentials.
func (ls *LocalStorage) CountActiveLeases(ctx context.Context, configID uint) (int64, error) {
	var n int64
	err := ls.db.WithContext(ctx).Model(&models.DynamicSecretLease{}).
		Where("config_id = ? AND status IN ?", configID, []string{"active", "revoke_failed"}).Count(&n).Error
	return n, err
}

// ListExpiredActiveLeases returns leases whose ExpiresAt is past `before` that still need
// their target credential dropped — active leases AND revoke_failed ones (whose earlier
// revoke failed, so their credential is still live). Ordered by id (stable) for the sweep.
// Without the revoke_failed inclusion such a credential would stay live past TTL forever,
// excluded from both the sweep and a manual retry.
func (ls *LocalStorage) ListExpiredActiveLeases(ctx context.Context, before time.Time) ([]*models.DynamicSecretLease, error) {
	var leases []*models.DynamicSecretLease
	if err := ls.db.WithContext(ctx).
		Where("status IN ? AND expires_at < ?", []string{"active", "revoke_failed"}, before).
		Order("id").Limit(maxUnboundedListRows).Find(&leases).Error; err != nil {
		return nil, err
	}
	return leases, nil
}
