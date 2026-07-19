package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateSecretVersionComment(_ context.Context, c *models.SecretVersionComment) error {
	return nil
}

func (m *MockStorage) ListSecretVersionComments(_ context.Context, _ uint) ([]models.SecretVersionComment, error) {
	return nil, nil
}

func (m *MockStorage) DeleteSecretVersionComment(_ context.Context, _ uint) error {
	return nil
}
