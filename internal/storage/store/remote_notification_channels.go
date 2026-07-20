// remote_notification_channels.go — RemoteStorage stubs for notification channel
// management. The REST API (/api/v1/notification-channels) is the remote surface;
// these methods are never invoked directly by a remote-storage caller (the CLI
// uses the REST endpoints via common.RemoteClient). All six are intentional stubs
// documented in remote_unsupported_completeness_test.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) ListNotificationChannels(_ context.Context) ([]*models.NotificationChannel, error) {
	return nil, remoteUnsupported("ListNotificationChannels")
}

func (rs *RemoteStorage) GetNotificationChannel(_ context.Context, _ uint) (*models.NotificationChannel, error) {
	return nil, remoteUnsupported("GetNotificationChannel")
}

func (rs *RemoteStorage) GetNotificationChannelByName(_ context.Context, _ string) (*models.NotificationChannel, error) {
	return nil, remoteUnsupported("GetNotificationChannelByName")
}

func (rs *RemoteStorage) CreateNotificationChannel(_ context.Context, _ *models.NotificationChannel) error {
	return remoteUnsupported("CreateNotificationChannel")
}

func (rs *RemoteStorage) UpdateNotificationChannel(_ context.Context, _ *models.NotificationChannel) error {
	return remoteUnsupported("UpdateNotificationChannel")
}

func (rs *RemoteStorage) DeleteNotificationChannel(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteNotificationChannel")
}
