package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.NotificationChannel), args.Error(1)
}

func (m *MockStorage) GetNotificationChannel(ctx context.Context, id uint) (*models.NotificationChannel, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.NotificationChannel), args.Error(1)
}

func (m *MockStorage) GetNotificationChannelByName(ctx context.Context, name string) (*models.NotificationChannel, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.NotificationChannel), args.Error(1)
}

func (m *MockStorage) CreateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error {
	args := m.Called(ctx, ch)
	return args.Error(0)
}

func (m *MockStorage) UpdateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error {
	args := m.Called(ctx, ch)
	return args.Error(0)
}

func (m *MockStorage) DeleteNotificationChannel(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) UpdateNotificationRetryPolicy(ctx context.Context, channelID uint, maxRetries, backoffMs int) error {
	args := m.Called(ctx, channelID, maxRetries, backoffMs)
	return args.Error(0)
}
