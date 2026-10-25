package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateRotationPolicy(_ context.Context, _ *models.RotationPolicy) error {
	return nil
}

func (m *MockStorage) GetRotationPolicy(_ context.Context, id uint) (*models.RotationPolicy, error) {
	return &models.RotationPolicy{ID: id}, nil
}

func (m *MockStorage) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	args := m.Called(ctx, projectID, environmentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RotationPolicy), args.Error(1)
}

func (m *MockStorage) UpdateRotationPolicyFields(_ context.Context, _ uint, _ storage.RotationPolicyFieldUpdate, _ time.Time) (bool, error) {
	return true, nil
}

func (m *MockStorage) DeleteRotationPolicy(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) GetRotationPolicyBySecret(ctx context.Context, secretID uint) (*models.RotationPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RotationPolicy), args.Error(1)
}

func (m *MockStorage) UpdateRotationState(ctx context.Context, policyID uint, state, errMsg string) error {
	args := m.Called(ctx, policyID, state, errMsg)
	return args.Error(0)
}
