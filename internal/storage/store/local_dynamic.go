// local_dynamic.go — dynamic-secrets persistence (ADR-035): configs and the
// issued leases whose expiry drives the auto-revoke sweep.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error) {
	if err := ls.db.WithContext(ctx).Create(c).Error; err != nil {
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
	if err := ls.db.WithContext(ctx).Where("config_id = ?", configID).Order("issued_at desc").Find(&ls2).Error; err != nil {
		return nil, err
	}
	return ls2, nil
}

func (ls *LocalStorage) UpdateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) error {
	return ls.db.WithContext(ctx).Save(l).Error
}

// CountActiveLeases returns the number of active leases for a config.
func (ls *LocalStorage) CountActiveLeases(ctx context.Context, configID uint) (int64, error) {
	var n int64
	err := ls.db.WithContext(ctx).Model(&models.DynamicSecretLease{}).
		Where("config_id = ? AND status = ?", configID, "active").Count(&n).Error
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
		Order("id").Find(&leases).Error; err != nil {
		return nil, err
	}
	return leases, nil
}
