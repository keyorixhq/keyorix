// local_rotation_policies.go — RotationPolicy operations for LocalStorage.
//
// Covers: CreateRotationPolicy, GetRotationPolicy, ListRotationPolicies,
// UpdateRotationPolicy, DeleteRotationPolicy.
//
// All operations use direct GORM queries; no network calls.
// For the remote (HTTP) equivalent see remote_rotation_policies.go.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func (ls *LocalStorage) CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error {
	return ls.db.WithContext(ctx).Create(p).Error
}

func (ls *LocalStorage) GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error) {
	var policy models.RotationPolicy
	if err := ls.db.WithContext(ctx).First(&policy, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("rotation policy not found")
		}
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}
	return &policy, nil
}

func (ls *LocalStorage) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	query := ls.db.WithContext(ctx).Model(&models.RotationPolicy{})
	if projectID != nil {
		query = query.Where("project_id = ?", *projectID)
	}
	if environmentID != nil {
		query = query.Where("environment_id = ?", *environmentID)
	}
	var policies []*models.RotationPolicy
	if err := query.Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}
	return policies, nil
}

func (ls *LocalStorage) UpdateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error {
	return ls.db.WithContext(ctx).Save(p).Error
}

func (ls *LocalStorage) DeleteRotationPolicy(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Delete(&models.RotationPolicy{}, id).Error
}
