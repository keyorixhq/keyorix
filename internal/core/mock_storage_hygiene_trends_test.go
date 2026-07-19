package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SaveHygieneTrendSnapshot implements storage.Storage for MockStorage.
func (m *MockStorage) SaveHygieneTrendSnapshot(ctx context.Context, snap *models.HygieneTrendSnapshot) error {
	args := m.Called(ctx, snap)
	return args.Error(0)
}

// ListHygieneTrendSnapshots implements storage.Storage for MockStorage.
func (m *MockStorage) ListHygieneTrendSnapshots(ctx context.Context, days int) ([]*models.HygieneTrendSnapshot, error) {
	args := m.Called(ctx, days)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.HygieneTrendSnapshot), args.Error(1)
}

// CountStalePATs implements storage.Storage for MockStorage.
func (m *MockStorage) CountStalePATs(ctx context.Context, threshold time.Time) (int, error) {
	args := m.Called(ctx, threshold)
	return args.Int(0), args.Error(1)
}

// CountExpiredPATs implements storage.Storage for MockStorage.
func (m *MockStorage) CountExpiredPATs(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// CountStaleMachineCredentials implements storage.Storage for MockStorage.
func (m *MockStorage) CountStaleMachineCredentials(ctx context.Context, threshold time.Time) (int, error) {
	args := m.Called(ctx, threshold)
	return args.Int(0), args.Error(1)
}
