// remote_notifications.go — in-app notifications for RemoteStorage.
//
// Notifications are processed server-side in remote mode; these are stubs. For
// the local (GORM) equivalent see local_notifications.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateNotification(_ context.Context, _ *models.Notification) (*models.Notification, error) {
	return nil, fmt.Errorf("CreateNotification not implemented for remote storage")
}

func (rs *RemoteStorage) ListNotifications(_ context.Context, _ uint, _ bool, _ int) ([]*models.Notification, error) {
	return nil, fmt.Errorf("ListNotifications not implemented for remote storage")
}

func (rs *RemoteStorage) CountUnreadNotifications(_ context.Context, _ uint) (int64, error) {
	return 0, fmt.Errorf("CountUnreadNotifications not implemented for remote storage")
}

func (rs *RemoteStorage) MarkNotificationRead(_ context.Context, _, _ uint) error {
	return fmt.Errorf("MarkNotificationRead not implemented for remote storage")
}

func (rs *RemoteStorage) MarkAllNotificationsRead(_ context.Context, _ uint) error {
	return fmt.Errorf("MarkAllNotificationsRead not implemented for remote storage")
}
