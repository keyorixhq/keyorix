package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
	args := m.Called(ctx, t)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SetupToken), args.Error(1)
}

func (m *MockStorage) GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SetupToken), args.Error(1)
}

func (m *MockStorage) GetSetupTokenByID(ctx context.Context, id uint) (*models.SetupToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SetupToken), args.Error(1)
}

func (m *MockStorage) SupersedeActiveSetupTokens(ctx context.Context, purpose, email string, projectID *uint) error {
	args := m.Called(ctx, purpose, email, projectID)
	return args.Error(0)
}

func (m *MockStorage) MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error) {
	args := m.Called(ctx, id, consumedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) MarkSetupTokenExpired(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error) {
	args := m.Called(ctx, purpose, email, since)
	return args.Get(0).(int64), args.Error(1)
}
