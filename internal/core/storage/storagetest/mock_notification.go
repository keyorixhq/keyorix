package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error) {
	args := m.Called(ctx, n)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Notification), args.Error(1)
}

func (m *MockStorage) ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error) {
	args := m.Called(ctx, userID, unreadOnly, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Notification), args.Error(1)
}

func (m *MockStorage) ListScopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope, unreadOnly bool, limit int) ([]*models.Notification, error) {
	args := m.Called(ctx, userID, scope, unreadOnly, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Notification), args.Error(1)
}

func (m *MockStorage) CountUnreadScopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope) (int64, error) {
	args := m.Called(ctx, userID, scope)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) MarkScopedNotificationRead(ctx context.Context, id, userID uint, scope storage.NotificationScope) error {
	return m.Called(ctx, id, userID, scope).Error(0)
}

func (m *MockStorage) MarkAllScopedNotificationsRead(ctx context.Context, userID uint, scope storage.NotificationScope) error {
	return m.Called(ctx, userID, scope).Error(0)
}

func (m *MockStorage) CountUnreadNotifications(ctx context.Context, userID uint) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) HasUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (bool, error) {
	args := m.Called(ctx, userID, nType, projectID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) GetUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (*models.Notification, error) {
	args := m.Called(ctx, userID, nType, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Notification), args.Error(1)
}

func (m *MockStorage) UpdateNotification(ctx context.Context, n *models.Notification) error {
	return m.Called(ctx, n).Error(0)
}

func (m *MockStorage) MarkNotificationRead(ctx context.Context, id, userID uint) error {
	return m.Called(ctx, id, userID).Error(0)
}

func (m *MockStorage) MarkAllNotificationsRead(ctx context.Context, userID uint) error {
	return m.Called(ctx, userID).Error(0)
}

func (m *MockStorage) CreateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockStorage) GetAlertEscalationPolicy(ctx context.Context, id uint) (*models.AlertEscalationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AlertEscalationPolicy), args.Error(1)
}

func (m *MockStorage) ListAlertEscalationPolicies(ctx context.Context) ([]models.AlertEscalationPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AlertEscalationPolicy), args.Error(1)
}

func (m *MockStorage) UpdateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockStorage) DeleteAlertEscalationPolicy(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

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
