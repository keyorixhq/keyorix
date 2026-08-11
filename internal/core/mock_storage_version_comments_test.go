package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateSecretVersionComment(ctx context.Context, c *models.SecretVersionComment) error {
	args := m.Called(ctx, c)
	return args.Error(0)
}

func (m *MockStorage) ListSecretVersionComments(ctx context.Context, secretID, versionID uint) ([]models.SecretVersionComment, error) {
	args := m.Called(ctx, secretID, versionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SecretVersionComment), args.Error(1)
}

func (m *MockStorage) DeleteSecretVersionComment(ctx context.Context, secretID, versionID, id uint) error {
	args := m.Called(ctx, secretID, versionID, id)
	return args.Error(0)
}
