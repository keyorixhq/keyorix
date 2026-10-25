package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, t)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) ListActivePersonalAccessTokens(ctx context.Context) ([]*models.PersonalAccessToken, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) RevokePersonalAccessToken(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error) {
	a := m.Called(ctx, userID)
	v, _ := a.Get(0).([]string)
	return v, a.Error(1)
}

func (m *MockStorage) TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	args := m.Called(ctx, id, usedAt, staleness)
	return args.Error(0)
}

func (m *MockStorage) ListExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]*models.PersonalAccessToken, error) {
	args := m.Called(ctx, userID, now)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) BulkRevokeExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]string, error) {
	args := m.Called(ctx, userID, now)
	v, _ := args.Get(0).([]string)
	return v, args.Error(1)
}

func (m *MockStorage) ListExpiringPATs(ctx context.Context, cutoff time.Time) ([]models.PersonalAccessToken, error) {
	args := m.Called(ctx, cutoff)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.PersonalAccessToken), args.Error(1)
}
