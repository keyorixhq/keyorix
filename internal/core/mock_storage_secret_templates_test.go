package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateSecretTemplate(ctx context.Context, t *models.SecretTemplate) error {
	args := m.Called(ctx, t)
	return args.Error(0)
}

func (m *MockStorage) GetSecretTemplate(ctx context.Context, id uint) (*models.SecretTemplate, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretTemplate), args.Error(1)
}

func (m *MockStorage) GetSecretTemplateByName(ctx context.Context, name string) (*models.SecretTemplate, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretTemplate), args.Error(1)
}

func (m *MockStorage) ListSecretTemplates(ctx context.Context) ([]*models.SecretTemplate, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretTemplate), args.Error(1)
}

func (m *MockStorage) UpdateSecretTemplateFields(ctx context.Context, id uint, f storage.SecretTemplateFieldUpdate, updatedAt time.Time) (bool, error) {
	args := m.Called(ctx, id, f, updatedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) DeleteSecretTemplate(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
